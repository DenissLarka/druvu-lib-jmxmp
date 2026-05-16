/*
 * Validation — JmxmpSerialFilter allow-list behaviour.
 *
 * The end-to-end round trips (ModularMatrixIT) already prove the allow-list
 * is not too tight (real JMX traffic flows through both filtered streams).
 * This pins the explicit allow/deny + resource-limit contract.
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import static org.testng.Assert.assertEquals;

import com.druvu.jmxmp.shared.JmxmpSerialFilter;
import java.io.ObjectInputFilter;
import java.io.ObjectInputFilter.Status;
import javax.management.ObjectName;
import org.testng.annotations.Test;

public class SerialFilterIT {

    private ObjectInputFilter.FilterInfo info(Class<?> c, long arrayLen, long depth, long refs) {
        return new ObjectInputFilter.FilterInfo() {
            public Class<?> serialClass() {
                return c;
            }

            public long arrayLength() {
                return arrayLen;
            }

            public long depth() {
                return depth;
            }

            public long references() {
                return refs;
            }

            public long streamBytes() {
                return 0;
            }
        };
    }

    private Status check(Class<?> c) {
        return JmxmpSerialFilter.wireFilter().checkInput(info(c, -1, 1, 1));
    }

    @Test
    public void allowsJmxAndSafeJdkTypes() {
        assertEquals(check(ObjectName.class), Status.ALLOWED, "JMX type must be allowed");
        assertEquals(check(javax.management.Attribute.class), Status.ALLOWED);
        assertEquals(check(javax.management.remote.message.CloseMessage.class), Status.ALLOWED);
        assertEquals(check(String.class), Status.ALLOWED);
        assertEquals(check(java.util.HashMap.class), Status.ALLOWED);
        assertEquals(check(java.math.BigInteger.class), Status.ALLOWED);
        assertEquals(check(java.time.Instant.class), Status.ALLOWED);
        assertEquals(check(Integer.class), Status.ALLOWED);
        // arrays: component type is unwrapped and re-checked
        assertEquals(check(ObjectName[].class), Status.ALLOWED);
        assertEquals(check(String[][].class), Status.ALLOWED);
        assertEquals(check(int[].class), Status.ALLOWED);
    }

    @Test
    public void rejectsEverythingOutsideTheAllowList() {
        assertEquals(check(java.io.File.class), Status.REJECTED, "java.io.* is not allow-listed");
        assertEquals(check(java.security.KeyStore.class), Status.REJECTED);
        assertEquals(check(SerialFilterIT.class), Status.REJECTED, "arbitrary app class must be rejected");
        assertEquals(check(java.io.File[].class), Status.REJECTED, "array of rejected type stays rejected");
    }

    @Test
    public void enforcesResourceLimits() {
        ObjectInputFilter f = JmxmpSerialFilter.wireFilter();
        assertEquals(f.checkInput(info(String.class, -1, JmxmpSerialFilter.MAX_DEPTH + 1, 1)), Status.REJECTED);
        assertEquals(f.checkInput(info(String.class, -1, 1, JmxmpSerialFilter.MAX_REFS + 1L)), Status.REJECTED);
        assertEquals(f.checkInput(info(String.class, JmxmpSerialFilter.MAX_ARRAY + 1L, 1, 1)), Status.REJECTED);
    }
}
