/*
 * AccessControlledMBeanServer.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The integration seam (PLAN-2.0.0 §7.7): an MBeanServerForwarder that, per
 * intercepted MBeanServer operation, builds the JmxAccessRequest for its §7.1
 * row and calls JmxmpAccessControl.checkAccess(Subject.current(), req) BEFORE
 * delegating. A thrown SecurityException means the call never reaches the real
 * MBeanServer. Replaces the deleted MBeanServerFileAccessController and the
 * abstract MBeanServerAccessController (no properties-file mechanism).
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
 * inside {@code ServerIntermediary}'s {@code Subject.callAs(authenticatedSubject, …)} (Phase&nbsp;1). Denial is a
 * {@link SecurityException}; the wrapped {@code MBeanServer} is then never touched. Default-deny is the policy's
 * responsibility ({@link JmxmpAccessControl#policy()} / a custom SPI); {@link JmxmpAccessControl#allowAll()} is a
 * deliberate no-op control for authentication-only servers.
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

    private void check(JmxAction action, ObjectName target, String member) {
        accessControl.checkAccess(Subject.current(), new JmxAccessRequest(action, target, member));
    }

    private void check(JmxAction action, ObjectName target) {
        check(action, target, null);
    }

    private void check(JmxAction action) {
        check(action, null, null);
    }

    // ---- registration / lifecycle (mutating) -------------------------------

    @Override
    public ObjectInstance createMBean(String className, ObjectName name)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException {
        check(JmxAction.REGISTER_MBEAN, name);
        return mbs.createMBean(className, name);
    }

    @Override
    public ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException, InstanceNotFoundException {
        check(JmxAction.REGISTER_MBEAN, name);
        return mbs.createMBean(className, name, loaderName);
    }

    @Override
    public ObjectInstance createMBean(String className, ObjectName name, Object[] params, String[] signature)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException {
        check(JmxAction.REGISTER_MBEAN, name);
        return mbs.createMBean(className, name, params, signature);
    }

    @Override
    public ObjectInstance createMBean(
            String className, ObjectName name, ObjectName loaderName, Object[] params, String[] signature)
            throws ReflectionException, InstanceAlreadyExistsException, MBeanRegistrationException, MBeanException,
                    NotCompliantMBeanException, InstanceNotFoundException {
        check(JmxAction.REGISTER_MBEAN, name);
        return mbs.createMBean(className, name, loaderName, params, signature);
    }

    @Override
    public ObjectInstance registerMBean(Object object, ObjectName name)
            throws InstanceAlreadyExistsException, MBeanRegistrationException, NotCompliantMBeanException {
        check(JmxAction.REGISTER_MBEAN, name);
        return mbs.registerMBean(object, name);
    }

    @Override
    public void unregisterMBean(ObjectName name) throws InstanceNotFoundException, MBeanRegistrationException {
        check(JmxAction.UNREGISTER_MBEAN, name);
        mbs.unregisterMBean(name);
    }

    // ---- instantiation (mutating) ------------------------------------------

    @Override
    public Object instantiate(String className) throws ReflectionException, MBeanException {
        check(JmxAction.INSTANTIATE);
        return mbs.instantiate(className);
    }

    @Override
    public Object instantiate(String className, ObjectName loaderName)
            throws ReflectionException, MBeanException, InstanceNotFoundException {
        check(JmxAction.INSTANTIATE);
        return mbs.instantiate(className, loaderName);
    }

    @Override
    public Object instantiate(String className, Object[] params, String[] signature)
            throws ReflectionException, MBeanException {
        check(JmxAction.INSTANTIATE);
        return mbs.instantiate(className, params, signature);
    }

    @Override
    public Object instantiate(String className, ObjectName loaderName, Object[] params, String[] signature)
            throws ReflectionException, MBeanException, InstanceNotFoundException {
        check(JmxAction.INSTANTIATE);
        return mbs.instantiate(className, loaderName, params, signature);
    }

    // ---- attributes --------------------------------------------------------

    @Override
    public Object getAttribute(ObjectName name, String attribute)
            throws MBeanException, AttributeNotFoundException, InstanceNotFoundException, ReflectionException {
        check(JmxAction.GET_ATTRIBUTE, name, attribute);
        return mbs.getAttribute(name, attribute);
    }

    @Override
    public AttributeList getAttributes(ObjectName name, String[] attributes)
            throws InstanceNotFoundException, ReflectionException {
        check(JmxAction.GET_ATTRIBUTE, name);
        return mbs.getAttributes(name, attributes);
    }

    @Override
    public void setAttribute(ObjectName name, Attribute attribute)
            throws InstanceNotFoundException, AttributeNotFoundException, InvalidAttributeValueException,
                    MBeanException, ReflectionException {
        check(JmxAction.SET_ATTRIBUTE, name, attribute == null ? null : attribute.getName());
        mbs.setAttribute(name, attribute);
    }

    @Override
    public AttributeList setAttributes(ObjectName name, AttributeList attributes)
            throws InstanceNotFoundException, ReflectionException {
        check(JmxAction.SET_ATTRIBUTE, name);
        return mbs.setAttributes(name, attributes);
    }

    // ---- invoke ------------------------------------------------------------

    @Override
    public Object invoke(ObjectName name, String operationName, Object[] params, String[] signature)
            throws InstanceNotFoundException, MBeanException, ReflectionException {
        check(JmxAction.INVOKE, name, operationName);
        return mbs.invoke(name, operationName, params, signature);
    }

    // ---- introspection / discovery (read-ish) ------------------------------

    @Override
    public ObjectInstance getObjectInstance(ObjectName name) throws InstanceNotFoundException {
        check(JmxAction.GET_OBJECT_INSTANCE, name);
        return mbs.getObjectInstance(name);
    }

    @Override
    public boolean isInstanceOf(ObjectName name, String className) throws InstanceNotFoundException {
        check(JmxAction.GET_OBJECT_INSTANCE, name);
        return mbs.isInstanceOf(name, className);
    }

    @Override
    public boolean isRegistered(ObjectName name) {
        check(JmxAction.GET_OBJECT_INSTANCE, name);
        return mbs.isRegistered(name);
    }

    @Override
    public MBeanInfo getMBeanInfo(ObjectName name)
            throws InstanceNotFoundException, IntrospectionException, ReflectionException {
        check(JmxAction.GET_MBEAN_INFO, name);
        return mbs.getMBeanInfo(name);
    }

    @Override
    public Set<ObjectInstance> queryMBeans(ObjectName name, QueryExp query) {
        check(JmxAction.QUERY);
        return mbs.queryMBeans(name, query);
    }

    @Override
    public Set<ObjectName> queryNames(ObjectName name, QueryExp query) {
        check(JmxAction.QUERY);
        return mbs.queryNames(name, query);
    }

    @Override
    public Integer getMBeanCount() {
        check(JmxAction.GET_DOMAINS);
        return mbs.getMBeanCount();
    }

    @Override
    public String getDefaultDomain() {
        check(JmxAction.GET_DOMAINS);
        return mbs.getDefaultDomain();
    }

    @Override
    public String[] getDomains() {
        check(JmxAction.GET_DOMAINS);
        return mbs.getDomains();
    }

    // ---- class loaders (connector infrastructure — NOT authorized) ---------
    //
    // getClassLoader/getClassLoaderFor/getClassLoaderRepository are NOT
    // remotely-invocable JMXMP client operations (there is no
    // MBeanServerRequestMessage for them). Their only callers are the
    // connector's own (de)serialization plumbing — notably
    // ServerIntermediary's constructor, which runs at connection-accept time
    // BEFORE any Subject.callAs, so Subject.current() is null there and a
    // default-deny control would (correctly) deny and thereby deadlock
    // connection setup. They are deliberately pass-through: classloader
    // handles are not the protected asset (attributes/operations/registration
    // are, and remain gated). Deviation from PLAN §7.1: the GET_CLASSLOADER
    // action is retained in the JmxAction taxonomy for API/SPI stability but
    // is not emitted by this forwarder (user-approved 2026-05-17, fixing the
    // 2.3 connection-setup regression that item 3.2 caught).

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
        check(JmxAction.ADD_NOTIFICATION_LISTENER, name);
        mbs.addNotificationListener(name, listener, filter, handback);
    }

    @Override
    public void addNotificationListener(
            ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException {
        check(JmxAction.ADD_NOTIFICATION_LISTENER, name);
        mbs.addNotificationListener(name, listener, filter, handback);
    }

    @Override
    public void removeNotificationListener(ObjectName name, NotificationListener listener)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.REMOVE_NOTIFICATION_LISTENER, name);
        mbs.removeNotificationListener(name, listener);
    }

    @Override
    public void removeNotificationListener(
            ObjectName name, NotificationListener listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.REMOVE_NOTIFICATION_LISTENER, name);
        mbs.removeNotificationListener(name, listener, filter, handback);
    }

    @Override
    public void removeNotificationListener(ObjectName name, ObjectName listener)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.REMOVE_NOTIFICATION_LISTENER, name);
        mbs.removeNotificationListener(name, listener);
    }

    @Override
    public void removeNotificationListener(
            ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException, ListenerNotFoundException {
        check(JmxAction.REMOVE_NOTIFICATION_LISTENER, name);
        mbs.removeNotificationListener(name, listener, filter, handback);
    }

    // ---- deserialize (deprecated in MBeanServer, still part of the contract) ----

    @Override
    @SuppressWarnings("deprecation")
    public ObjectInputStream deserialize(ObjectName name, byte[] data) throws OperationsException {
        check(JmxAction.DESERIALIZE, name);
        return mbs.deserialize(name, data);
    }

    @Override
    @SuppressWarnings("deprecation")
    public ObjectInputStream deserialize(String className, byte[] data)
            throws OperationsException, ReflectionException {
        check(JmxAction.DESERIALIZE);
        return mbs.deserialize(className, data);
    }

    @Override
    @SuppressWarnings("deprecation")
    public ObjectInputStream deserialize(String className, ObjectName loaderName, byte[] data)
            throws OperationsException, ReflectionException, InstanceNotFoundException {
        check(JmxAction.DESERIALIZE);
        return mbs.deserialize(className, loaderName, data);
    }
}
