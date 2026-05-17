package com.druvu.jmxmp.it;

import java.util.StringJoiner;
import javax.security.auth.Subject;

/**
 * {@link CallerMBean} implementation. {@link #whoAmI()} reads {@code Subject.current()} — the modern (post-JEP-486)
 * identity idiom — so the integration test can assert that the SASL-authenticated subject is propagated all the way
 * into MBean code by the Phase&nbsp;1 {@code Subject.callAs} migration.
 */
public class Caller implements CallerMBean {

    @Override
    public String whoAmI() {
        Subject s = Subject.current();
        if (s == null || s.getPrincipals().isEmpty()) {
            return "<none>";
        }
        StringJoiner j = new StringJoiner(",");
        s.getPrincipals().forEach(p -> j.add(p.getName()));
        return j.toString();
    }
}
