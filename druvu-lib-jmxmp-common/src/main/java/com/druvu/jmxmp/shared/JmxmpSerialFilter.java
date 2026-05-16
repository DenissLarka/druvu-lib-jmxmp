/*
 * JmxmpSerialFilter.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * An opinionated, default-deny ObjectInputFilter applied to every wire
 * deserialization the library performs (the JMXMP message stream and the
 * MBean payload stream). Shrinks the inherent Java-deserialization attack
 * surface of JMXMP to a JMX + safe-JDK allow-list; deployers extend it for
 * their own MBean parameter/return types via a system property. Dual-licensed:
 * GPL v2 only with the Classpath exception, or CDDL v1.0. See the LICENSE
 * file at the repo root.
 */

package com.druvu.jmxmp.shared;

import java.io.ObjectInputFilter;
import java.util.ArrayList;
import java.util.List;

/**
 * Built-in serialization allow-list for JMXMP wire data.
 *
 * <p>JMXMP transfers serialized Java objects in both directions; this filter is the library's default-deny floor for
 * that surface. It <strong>allows</strong> only:
 *
 * <ul>
 *   <li>the JMX object model and the JMXMP protocol/message types — {@code javax.management.*};
 *   <li>authentication value types — {@code javax.security.auth.*};
 *   <li>safe JDK value types — {@code java.lang.*}, {@code java.util.*}, {@code java.math.*}, {@code java.time.*};
 *   <li>primitives and arrays of any of the above (component type is unwrapped and re-checked);
 *   <li>any class whose name matches a deployer-supplied pattern (below).
 * </ul>
 *
 * <p>Everything else is <strong>rejected</strong>. The classic Java deserialization gadget sinks (commons-collections,
 * {@code com.sun.rowset.JdbcRowSetImpl}, Xalan {@code TemplatesImpl}, {@code sun.*}, {@code javassist}, {@code bsh}, …)
 * all fall outside the allow-list and are refused without needing to be enumerated.
 *
 * <p><b>Extending it.</b> Real MBeans exchange application types this list cannot know in advance. Add them via the
 * {@value #ALLOW_PROPERTY} system property — a {@code ;}-separated list of class-name prefixes, e.g.
 * {@code -Dcom.druvu.jmxmp.serial.allow=com.acme.metrics.;com.acme.dto.}. A trailing prefix matches that package and
 * its subpackages. This is process-wide and reaches both wire deserialization sites uniformly (the same ergonomics as
 * {@code jdk.serialFilter}).
 *
 * <p><b>Composition.</b> The returned filter is merged with any process-wide {@code jdk.serialFilter} via
 * {@link ObjectInputFilter#merge}: a reject from <em>either</em> wins, so this never weakens a stricter deployer
 * filter, and a deployer filter can only tighten this one.
 *
 * <p><b>Resource limits.</b> Independently of class allow-listing, oversized graphs are rejected
 * (depth&nbsp;&gt;&nbsp;{@value #MAX_DEPTH}, refs&nbsp;&gt;&nbsp;{@value #MAX_REFS},
 * array&nbsp;length&nbsp;&gt;&nbsp;{@value #MAX_ARRAY}) to blunt decompression/quadratic-blowup DoS.
 */
public final class JmxmpSerialFilter {

    /** System property: {@code ;}-separated extra allowed class-name prefixes. */
    public static final String ALLOW_PROPERTY = "com.druvu.jmxmp.serial.allow";

    /** Max object-graph depth; deeper graphs are rejected regardless of class. */
    public static final int MAX_DEPTH = 64;
    /** Max total back-references; larger graphs are rejected. */
    public static final int MAX_REFS = 1_000_000;
    /** Max single-array length; larger arrays are rejected. */
    public static final int MAX_ARRAY = 1_000_000;

    private static final String[] BASE_ALLOWED = {
        "javax.management.", "javax.security.auth.", "java.lang.", "java.util.", "java.math.", "java.time."
    };

    private static volatile ObjectInputFilter cached;

    private JmxmpSerialFilter() {}

    /**
     * The shared wire filter — built once from {@value #ALLOW_PROPERTY} and the process-wide filter, then cached. Apply
     * with {@link java.io.ObjectInputStream#setObjectInputFilter} on every stream that reads peer data.
     */
    public static ObjectInputFilter wireFilter() {
        ObjectInputFilter f = cached;
        if (f == null) {
            f = build(System.getProperty(ALLOW_PROPERTY));
            cached = f;
        }
        return f;
    }

    // Visible for testing — bypasses the system property + cache.
    static ObjectInputFilter build(String extraPrefixes) {
        List<String> allow = new ArrayList<>(List.of(BASE_ALLOWED));
        if (extraPrefixes != null && !extraPrefixes.isBlank()) {
            for (String p : extraPrefixes.split(";")) {
                String t = p.trim();
                if (!t.isEmpty()) {
                    allow.add(t);
                }
            }
        }
        String[] prefixes = allow.toArray(new String[0]);
        ObjectInputFilter base = info -> evaluate(info, prefixes);

        ObjectInputFilter process = ObjectInputFilter.Config.getSerialFilter();
        return process == null ? base : ObjectInputFilter.merge(base, process);
    }

    private static ObjectInputFilter.Status evaluate(ObjectInputFilter.FilterInfo info, String[] prefixes) {
        if (info.depth() > MAX_DEPTH
                || info.references() > MAX_REFS
                || (info.arrayLength() >= 0 && info.arrayLength() > MAX_ARRAY)) {
            return ObjectInputFilter.Status.REJECTED;
        }
        Class<?> c = info.serialClass();
        if (c == null) {
            // Not a class check (primitive, array length, refs) — defer.
            return ObjectInputFilter.Status.UNDECIDED;
        }
        while (c.isArray()) {
            c = c.getComponentType();
        }
        if (c.isPrimitive()) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        String name = c.getName();
        for (String p : prefixes) {
            if (name.startsWith(p)) {
                return ObjectInputFilter.Status.ALLOWED;
            }
        }
        return ObjectInputFilter.Status.REJECTED;
    }
}
