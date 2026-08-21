package net.rafalohaki.veloauth.authserver;

import io.netty.channel.Channel;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/** Parent-classloader facade for the separately downloaded ViaVersion runtime. */
final class ManagedProtocolRuntime implements ProtocolRuntime {

    private static final String BOOTSTRAP_CLASS =
            "net.rafalohaki.veloauth.authserver.runtime.ViaRuntimeBootstrap";
    private static final String PRIVATE_BOOTSTRAP_PREFIX =
            "net.rafalohaki.veloauth.authserver.runtime.";
    private static final String PRIVATE_VIA_PREFIX = "com.viaversion.";
    private static final String CHANNEL_PARAM = "channel";
    private static final int MAXIMUM_BOOTSTRAP_CLASS_BYTES = 1024 * 1024;
    private static final ReentrantLock RUNTIME_INITIALIZATION_LOCK = new ReentrantLock();

    private final RuntimeClassLoader classLoader;
    private final Object delegate;
    private final String runtimeVersion;
    private final Method supportsProtocol;
    private final Method inject;
    private final Method clientProtocol;
    private final Method sendVelocityForwardingRequest;
    private final Method minimumProtocol;
    private final Method maximumProtocol;
    private final Method minimumVersionName;
    private final Method maximumVersionName;
    private final Method close;
    private final RuntimeSnapshotManager snapshots;
    private final RuntimeSnapshotManager.RuntimeCandidate candidate;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean operationalConfirmed = new AtomicBoolean();

    private ManagedProtocolRuntime(
            RuntimeClassLoader classLoader,
            Object delegate,
            String runtimeVersion,
            RuntimeSnapshotManager snapshots,
            RuntimeSnapshotManager.RuntimeCandidate candidate) {
        this.classLoader = classLoader;
        this.delegate = delegate;
        this.runtimeVersion = Objects.requireNonNull(runtimeVersion, "runtimeVersion");
        this.snapshots = snapshots;
        this.candidate = candidate;
        Class<?> type = delegate.getClass();
        try {
            supportsProtocol = type.getMethod("supportsProtocol", int.class);
            inject = type.getMethod("inject", Channel.class);
            clientProtocol = type.getMethod("clientProtocol", Channel.class);
            sendVelocityForwardingRequest = type.getMethod(
                    "sendVelocityForwardingRequest", Channel.class, int.class, Runnable.class);
            minimumProtocol = type.getMethod("minimumProtocol");
            maximumProtocol = type.getMethod("maximumProtocol");
            minimumVersionName = type.getMethod("minimumVersionName");
            maximumVersionName = type.getMethod("maximumVersionName");
            close = type.getMethod("close");
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Embedded protocol runtime bootstrap contract is incompatible", e);
        }
    }

    static ManagedProtocolRuntime open(Path dataDirectory, Logger logger, String pluginVersion) {
        return open(dataDirectory, logger, pluginVersion,
                runtime -> EmbeddedLimboRuntimeProbe.verify(runtime, logger));
    }

    static ManagedProtocolRuntime open(
            Path dataDirectory,
            Logger logger,
            String pluginVersion,
            java.util.Set<RuntimeArtifactDescriptor> approvedDescriptors) {
        return open(dataDirectory, logger, pluginVersion,
                runtime -> EmbeddedLimboRuntimeProbe.verify(runtime, logger),
                approvedDescriptors);
    }

    static ManagedProtocolRuntime open(
            Path dataDirectory,
            Logger logger,
            String pluginVersion,
            RuntimeValidator validator) {
        return open(
                dataDirectory,
                logger,
                pluginVersion,
                validator,
                new RuntimeSnapshotManager(dataDirectory, logger));
    }

    static ManagedProtocolRuntime open(
            Path dataDirectory,
            Logger logger,
            String pluginVersion,
            RuntimeValidator validator,
            java.util.Set<RuntimeArtifactDescriptor> approvedDescriptors) {
        return open(
                dataDirectory,
                logger,
                pluginVersion,
                validator,
                new RuntimeSnapshotManager(dataDirectory, logger, approvedDescriptors));
    }

    private static ManagedProtocolRuntime open(
            Path dataDirectory,
            Logger logger,
            String pluginVersion,
            RuntimeValidator validator,
            RuntimeSnapshotManager snapshots) {
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        Objects.requireNonNull(logger, "logger");
        Objects.requireNonNull(pluginVersion, "pluginVersion");
        Objects.requireNonNull(validator, "validator");
        Objects.requireNonNull(snapshots, "snapshots");
        IllegalStateException aggregate = new IllegalStateException(
                "No verified embedded protocol runtime could be initialized");
        for (RuntimeSnapshotManager.RuntimeCandidate candidate : snapshots.startupCandidates()) {
            try {
                Path artifact = snapshots.resolve(candidate);
                ManagedProtocolRuntime runtime = open(
                        artifact,
                        dataDirectory.resolve("runtime-config"),
                        logger,
                        pluginVersion,
                        candidate.artifact().version(),
                        snapshots,
                        candidate);
                return validated(runtime, validator);
            } catch (RuntimeException | LinkageError e) {
                snapshots.recordFailed(candidate, e);
                aggregate.addSuppressed(e);
            }
        }
        throw aggregate;
    }

    /** Returns the runtime once the validator accepts it; closes and rethrows otherwise. */
    private static ManagedProtocolRuntime validated(
            ManagedProtocolRuntime runtime, RuntimeValidator validator) {
        try {
            validator.validate(runtime);
            return runtime;
        } catch (RuntimeException | LinkageError validationFailure) {
            closeSuppressing(runtime, validationFailure);
            throw validationFailure;
        }
    }

    private static void closeSuppressing(ManagedProtocolRuntime runtime, Throwable primary) {
        try {
            runtime.close();
        } catch (RuntimeException | LinkageError closeFailure) {
            primary.addSuppressed(closeFailure);
        }
    }

    static ManagedProtocolRuntime open(
            Path artifact,
            Path runtimeConfigDirectory,
            Logger logger,
            String pluginVersion) {
        return open(artifact, runtimeConfigDirectory, logger, pluginVersion,
                net.rafalohaki.veloauth.BuildConstants.EMBEDDED_VIAVERSION_VERSION,
                null,
                null);
    }

    private static ManagedProtocolRuntime open(
            Path artifact,
            Path runtimeConfigDirectory,
            Logger logger,
            String pluginVersion,
            String runtimeVersion,
            RuntimeSnapshotManager snapshots,
            RuntimeSnapshotManager.RuntimeCandidate candidate) {
        RUNTIME_INITIALIZATION_LOCK.lock();
        try {
            RuntimeClassLoader loader = null;
            Object delegate = null;
            try {
                URL artifactUrl = Objects.requireNonNull(artifact, "artifact").toUri().toURL();
                loader = new RuntimeClassLoader(
                        new URL[]{artifactUrl}, ManagedProtocolRuntime.class.getClassLoader());
                Class<?> bootstrap = Class.forName(BOOTSTRAP_CLASS, true, loader);
                delegate = bootstrap
                        .getConstructor(Path.class, Logger.class, String.class)
                        .newInstance(runtimeConfigDirectory, logger, pluginVersion);
                return new ManagedProtocolRuntime(
                        loader, delegate, runtimeVersion, snapshots, candidate);
            } catch (IOException | ReflectiveOperationException | RuntimeException | LinkageError e) {
                closeDelegate(delegate, e);
                closeLoader(loader);
                throw new IllegalStateException("Unable to initialize embedded protocol translation runtime", e);
            }
        } finally {
            RUNTIME_INITIALIZATION_LOCK.unlock();
        }
    }

    @Override
    public boolean supportsProtocol(int protocol) {
        return (Boolean) invoke(supportsProtocol, protocol);
    }

    @Override
    public int minimumProtocol() {
        return (Integer) invoke(minimumProtocol);
    }

    @Override
    public int maximumProtocol() {
        return (Integer) invoke(maximumProtocol);
    }

    @Override
    public String minimumVersionName() {
        return (String) invoke(minimumVersionName);
    }

    @Override
    public String maximumVersionName() {
        return (String) invoke(maximumVersionName);
    }

    @Override
    public String runtimeVersion() {
        return runtimeVersion;
    }

    @Override
    public void inject(Channel channel) {
        invoke(inject, Objects.requireNonNull(channel, CHANNEL_PARAM));
    }

    @Override
    public int clientProtocol(Channel channel) {
        return (Integer) invoke(clientProtocol, Objects.requireNonNull(channel, CHANNEL_PARAM));
    }

    @Override
    public void confirmOperational() {
        if (snapshots == null || candidate == null
                || candidate.source() != RuntimeSnapshotManager.CandidateSource.PENDING) {
            return;
        }
        if (closed.get()) {
            throw new IllegalStateException("Closed embedded protocol runtime cannot be activated");
        }
        if (!operationalConfirmed.compareAndSet(false, true)) {
            return;
        }
        try {
            snapshots.recordSuccessful(candidate);
        } catch (RuntimeException activationFailure) {
            operationalConfirmed.set(false);
            throw activationFailure;
        }
    }

    @Override
    public void sendVelocityForwardingRequest(
            Channel channel, int transactionId, Runnable loginContinuation) {
        invoke(sendVelocityForwardingRequest,
                Objects.requireNonNull(channel, CHANNEL_PARAM),
                transactionId,
                Objects.requireNonNull(loginContinuation, "loginContinuation"));
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        Throwable failure = null;
        try {
            invoke(close);
        } catch (RuntimeException | LinkageError e) {
            failure = e;
        }
        try {
            classLoader.close();
        } catch (IOException e) {
            if (failure == null) {
                failure = new IllegalStateException("Unable to close embedded protocol runtime classloader", e);
            } else {
                failure.addSuppressed(e);
            }
        }
        if (failure instanceof RuntimeException runtimeFailure) {
            throw runtimeFailure;
        }
        if (failure instanceof LinkageError linkageFailure) {
            throw linkageFailure;
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace") // Deliberately unwrap the child runtime's real cause.
    private Object invoke(Method method, Object... arguments) {
        if (closed.get() && !method.equals(close)) {
            throw new IllegalStateException("Embedded protocol runtime is closed");
        }
        try {
            return method.invoke(delegate, arguments);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Embedded protocol runtime method is inaccessible", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("Embedded protocol runtime call failed", cause);
        }
    }

    private static void closeLoader(RuntimeClassLoader loader) {
        if (loader == null) {
            return;
        }
        try {
            loader.close();
        } catch (IOException ignored) {
            // The initialization exception remains the actionable root cause.
        }
    }

    private static void closeDelegate(Object delegate, Throwable initializationFailure) {
        if (delegate == null) {
            return;
        }
        try {
            delegate.getClass().getMethod("close").invoke(delegate);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError closeFailure) {
            initializationFailure.addSuppressed(closeFailure);
        }
    }

    @FunctionalInterface
    interface RuntimeValidator {
        void validate(ManagedProtocolRuntime runtime);
    }

    /** Child-first only for the downloaded implementation and its tiny VeloAuth bootstrap. */
    private static final class RuntimeClassLoader extends URLClassLoader {
        private final ClassLoader bootstrapResourceLoader;
        private final ReentrantLock classLoadingLock = new ReentrantLock();

        private RuntimeClassLoader(URL[] urls, ClassLoader parent) {
            super("VeloAuth-EmbeddedProtocolRuntime", urls, parent);
            bootstrapResourceLoader = parent;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!name.startsWith(PRIVATE_BOOTSTRAP_PREFIX) && !name.startsWith(PRIVATE_VIA_PREFIX)) {
                return super.loadClass(name, resolve);
            }
            classLoadingLock.lock();
            try {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    loaded = name.startsWith(PRIVATE_BOOTSTRAP_PREFIX)
                            ? defineBootstrapClass(name)
                            : findClass(name);
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            } finally {
                classLoadingLock.unlock();
            }
        }

        private Class<?> defineBootstrapClass(String name) throws ClassNotFoundException {
            String resourceName = name.replace('.', '/') + ".class";
            try (InputStream input = bootstrapResourceLoader.getResourceAsStream(resourceName)) {
                if (input == null) {
                    throw new ClassNotFoundException(name);
                }
                byte[] bytecode = RuntimeIo.readBounded(
                        input,
                        MAXIMUM_BOOTSTRAP_CLASS_BYTES,
                        "Embedded protocol runtime bootstrap class exceeds its maximum size");
                return defineClass(name, bytecode, 0, bytecode.length);
            } catch (IOException e) {
                throw new ClassNotFoundException(name, e);
            }
        }
    }
}
