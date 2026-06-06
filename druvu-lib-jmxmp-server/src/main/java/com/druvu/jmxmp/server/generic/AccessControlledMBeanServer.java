/*
 * AccessControlledMBeanServer.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The integration seam: an MBeanServerForwarder that, per intercepted
 * MBeanServer operation, builds the JmxAccessRequest for its row and calls
 * JmxmpAccessControl.checkAccess(Subject.current(), req) BEFORE delegating. A
 * thrown SecurityException means the call never reaches the real MBeanServer.
 * Remote MBean lifecycle (create/register/unregister/instantiate) and the
 * deprecated deserialize forms are permanently denied here, independent of the
 * configured access control. Replaces the deleted MBeanServerFileAccessController.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.server.generic;

import com.druvu.jmxmp.shared.JmxAccessRequest;
import com.druvu.jmxmp.shared.JmxAction;
import com.druvu.jmxmp.shared.JmxmpAccessControl;
import java.io.ObjectInputStream;
import java.util.Set;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.IntrospectionException;
import javax.management.InvalidAttributeValueException;
import javax.management.ListenerNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanInfo;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServer;
import javax.management.NotCompliantMBeanException;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.OperationsException;
import javax.management.QueryExp;
import javax.management.ReflectionException;
import javax.management.loading.ClassLoaderRepository;
import javax.management.remote.MBeanServerForwarder;
import javax.security.auth.Subject;

/**
 * {@link MBeanServerForwarder} that authorizes every intercepted operation through a {@link JmxmpAccessControl} before
 * forwarding it to the wrapped {@code MBeanServer}.
 *
 * <p>The subject comes <strong>only</strong> from {@link Subject#current()} — this is correct because the request runs
 * inside {@code ServerIntermediary}'s {@code Subject.callAs(authenticatedSubject, …)}. Denial is a
 * {@link SecurityException}; the wrapped {@code MBeanServer} is then never touched. Default-deny is the policy's
 * responsibility ({@link JmxmpAccessControl#policy()} / a custom SPI); {@link JmxmpAccessControl#allowAll()} is a
 * deliberate no-op control for authentication-only servers.
 *
 * <p><b>Permanently denied, regardless of the control.</b> Remote MBean lifecycle ({@code createMBean},
 * {@code registerMBean}, {@code unregisterMBean}, {@code instantiate}) and the deprecated {@code deserialize(...)}
 * forms are refused here directly via {@link #denyManagement(String)} — they are not a {@link JmxAction} verb, no
 * policy can grant them, and {@code allowAll()} does not relax them. The forwarder is installed on every secured server
 * (with {@code allowAll()} as the default control when none is configured), so this denial is an invariant of the
 * connector, not a function of the deployer's policy. The only mutation a remote client can perform is to an existing
 * MBean.
 *
 * <p>Package-private and internal: it is installed by {@code GenericConnectorServerEngineImpl} and is not part of the
 * public API.
 */
final class AccessControlledMBeanServer implements MBeanServerForwarder {

    private final JmxmpAccessControl accessControl;
    private MBeanServer mbs;

    AccessControlledMBeanServer(JmxmpAccessControl accessControl) {
        this.accessControl = accessControl;
    }

    @Override
    public MBeanServer getMBeanServer() {
        return mbs;
    }

    @Override
    public void setMBeanServer(MBeanServer mbs) {
        if (mbs == null) {
            throw new IllegalArgumentException("Null MBeanServer");
        }
        if (this.mbs != null) {
            throw new IllegalArgumentException("MBeanServer object already initialized");
        }
        this.mbs = mbs;
    }

    private void check(JmxAction action, ObjectName target) {
        accessControl.checkAccess(Subject.current(), new JmxAccessRequest(action, target));
    }

    private void check(JmxAction action) {
        check(action, null);
    }

    /**
     * Permanently un-authorizable remote MBean lifecycle / deserialization: refused for everyone, independent of the
     * configured {@link JmxmpAccessControl} — there is no verb to grant it and {@code allowAll()} does not relax it.
     */
    private SecurityException denyManagement(String op) {
        return new SecurityException("Access denied: '" + op
                + "' — remote MBean lifecycle/deserialization is permanently disabled by druvu-lib-jmxmp; "
                + "no grant can permit it and allowAll() does not relax it.");
    }

    // ---- registration / instantiation / deserialize (permanently denied) ----

    @Override
    public ObjectInstance createMBean(String className, ObjectName name)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException {
        throw denyManagement("createMBean");
    }

    @Override
    public ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException, InstanceNotFoundException {
        throw denyManagement("createMBean");
    }

    @Override
    public ObjectInstance createMBean(String className, ObjectName name, Object[] params, String[] signature)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException {
        throw denyManagement("createMBean");
    }

    @Override
    public ObjectInstance createMBean(
            String className, ObjectName name, ObjectName loaderName, Object[] params, String[] signature)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException, InstanceNotFoundException {
        throw denyManagement("createMBean");
    }

    @Override
    public ObjectInstance registerMBean(Object object, ObjectName name)
            throws InstanceAlreadyExistsException, MBeanRegistrationException, NotCompliantMBeanException {
        throw denyManagement("registerMBean");
    }

    @Override
    public void unregisterMBean(ObjectName name) throws InstanceNotFoundException, MBeanRegistrationException {
        throw denyManagement("unregisterMBean");
    }

    @Override
    public Object instantiate(String className) throws ReflectionException, MBeanException {
        throw denyManagement("instantiate");
    }

    @Override
    public Object instantiate(String className, ObjectName loaderName)
            throws ReflectionException, MBeanException, InstanceNotFoundException {
        throw denyManagement("instantiate");
    }

    @Override
    public Object instantiate(String className, Object[] params, String[] signature)
            throws ReflectionException, MBeanException {
        throw denyManagement("instantiate");
    }

    @Override
    public Object instantiate(String className, ObjectName loaderName, Object[] params, String[] signature)
            throws ReflectionException, MBeanException, InstanceNotFoundException {
        throw denyManagement("instantiate");
    }

    @Override
    @SuppressWarnings("deprecation")
    public ObjectInputStream deserialize(ObjectName name, byte[] data) throws OperationsException {
        throw denyManagement("deserialize");
    }

    @Override
    @SuppressWarnings("deprecation")
    public ObjectInputStream deserialize(String className, byte[] data)
            throws OperationsException, ReflectionException {
        throw denyManagement("deserialize");
    }

    @Override
    @SuppressWarnings("deprecation")
    public ObjectInputStream deserialize(String className, ObjectName loaderName, byte[] data)
            throws OperationsException, ReflectionException, InstanceNotFoundException {
        throw denyManagement("deserialize");
    }

    // ---- attributes --------------------------------------------------------

    @Override
    public Object getAttribute(ObjectName name, String attribute)
            throws MBeanException, AttributeNotFoundException, InstanceNotFoundException, ReflectionException {
        check(JmxAction.READ, name);
        return mbs.getAttribute(name, attribute);
    }

    @Override
    public AttributeList getAttributes(ObjectName name, String[] attributes)
            throws InstanceNotFoundException, ReflectionException {
        check(JmxAction.READ, name);
        return mbs.getAttributes(name, attributes);
    }

    @Override
    public void setAttribute(ObjectName name, Attribute attribute)
            throws InstanceNotFoundException, AttributeNotFoundException, InvalidAttributeValueException,
                    MBeanException, ReflectionException {
        check(JmxAction.WRITE, name);
        mbs.setAttribute(name, attribute);
    }

    @Override
    public AttributeList setAttributes(ObjectName name, AttributeList attributes)
            throws InstanceNotFoundException, ReflectionException {
        check(JmxAction.WRITE, name);
        return mbs.setAttributes(name, attributes);
    }

    // ---- invoke ------------------------------------------------------------

    @Override
    public Object invoke(ObjectName name, String operationName, Object[] params, String[] signature)
            throws InstanceNotFoundException, MBeanException, ReflectionException {
        check(JmxAction.INVOKE, name);
        return mbs.invoke(name, operationName, params, signature);
    }

    // ---- introspection / discovery (READ) ----------------------------------

    @Override
    public ObjectInstance getObjectInstance(ObjectName name) throws InstanceNotFoundException {
        check(JmxAction.READ, name);
        return mbs.getObjectInstance(name);
    }

    @Override
    public boolean isInstanceOf(ObjectName name, String className) throws InstanceNotFoundException {
        check(JmxAction.READ, name);
        return mbs.isInstanceOf(name, className);
    }

    @Override
    public boolean isRegistered(ObjectName name) {
        check(JmxAction.READ, name);
        return mbs.isRegistered(name);
    }

    @Override
    public MBeanInfo getMBeanInfo(ObjectName name)
            throws InstanceNotFoundException, IntrospectionException, ReflectionException {
        check(JmxAction.READ, name);
        return mbs.getMBeanInfo(name);
    }

    @Override
    public Set<ObjectInstance> queryMBeans(ObjectName name, QueryExp query) {
        check(JmxAction.READ);
        return mbs.queryMBeans(name, query);
    }

    @Override
    public Set<ObjectName> queryNames(ObjectName name, QueryExp query) {
        check(JmxAction.READ);
        return mbs.queryNames(name, query);
    }

    @Override
    public Integer getMBeanCount() {
        check(JmxAction.READ);
        return mbs.getMBeanCount();
    }

    @Override
    public String getDefaultDomain() {
        check(JmxAction.READ);
        return mbs.getDefaultDomain();
    }

    @Override
    public String[] getDomains() {
        check(JmxAction.READ);
        return mbs.getDomains();
    }

    // ---- class loaders (connector infrastructure — NOT authorized) ---------
    //
    // getClassLoader/getClassLoaderFor/getClassLoaderRepository are NOT
    // remotely-invocable JMXMP client operations (there is no
    // MBeanServerRequestMessage for them). Their only callers are the
    // connector's own (de)serialization plumbing — notably
    // ServerIntermediary's constructor, which runs at connection-accept time
    // BEFORE any Subject.callAs, so Subject.current() is null there and any
    // check (deny or otherwise) would break connection setup. They are
    // deliberately pass-through: classloader handles are not the protected
    // asset (attributes/operations are, and remain gated; lifecycle is denied
    // outright above).

    @Override
    public ClassLoader getClassLoaderFor(ObjectName mbeanName) throws InstanceNotFoundException {
        return mbs.getClassLoaderFor(mbeanName);
    }

    @Override
    public ClassLoader getClassLoader(ObjectName loaderName) throws InstanceNotFoundException {
        return mbs.getClassLoader(loaderName);
    }

    @Override
    public ClassLoaderRepository getClassLoaderRepository() {
        return mbs.getClassLoaderRepository();
    }

    // ---- notifications -----------------------------------------------------

    @Override
    public void addNotificationListener(
            ObjectName name, NotificationListener listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException {
        check(JmxAction.NOTIFY, name);
        mbs.addNotificationListener(name, listener, filter, handback);
    }

    @Override
    public void addNotificationListener(
            ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException {
        check(JmxAction.NOTIFY, name);
        mbs.addNotificationListener(name, listener, filter, handback);
    }

    @Override
    public void removeNotificationListener(ObjectName name, NotificationListener listener)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.NOTIFY, name);
        mbs.removeNotificationListener(name, listener);
    }

    @Override
    public void removeNotificationListener(
            ObjectName name, NotificationListener listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.NOTIFY, name);
        mbs.removeNotificationListener(name, listener, filter, handback);
    }

    @Override
    public void removeNotificationListener(ObjectName name, ObjectName listener)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.NOTIFY, name);
        mbs.removeNotificationListener(name, listener);
    }

    @Override
    public void removeNotificationListener(
            ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.NOTIFY, name);
        mbs.removeNotificationListener(name, listener, filter, handback);
    }
}
