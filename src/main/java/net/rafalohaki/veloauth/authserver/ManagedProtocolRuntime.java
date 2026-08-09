package net.rafalohaki.veloauth.authserver;

import io.netty.channel.Channel;
import org.slf4j.Logger;

import java.io.ByteArrayOutputStream;
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
    private static final ReentrantLock RUNTIME_INITIALIZATION_LOCK = new ReentrantLock();

    private final RuntimeClassLoader classLoader;
    private final Object delegate;
    private final String runtimeVersion;
    private final Method supportsProtocol;
    private final Method inject;
    private final Method sendVelocityForwardingRequest;
    private final Method minimumProtocol;
    private final Method maximumProtocol;
    private final Method minimumVersionName;
    private final Method maximumVersionName;
    private final Method close;
    private final AtomicBoolean closed = new AtomicBoolean();

    private ManagedProtocolRuntime(RuntimeClassLoader classLoader, Object delegate, String runtimeVersion) {
        this.classLoader = classLoader;
        this.delegate = delegate;
        this.runtimeVersion = Objects.requireNonNull(runtimeVersion, "runtimeVersion");
        Class<?> type = delegate.getClass();
        try {
            supportsProtocol = type.getMethod("supportsProtocol", int.class);
            inject = type.getMethod("inject", Channel.class);
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
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        Objects.requireNonNull(logger, "logger");
        Objects.requireNonNull(pluginVersion, "pluginVersion");
        RuntimeSnapshotManager snapshots = new RuntimeSnapshotManager(dataDirectory, logger);
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
                        candidate.artifact().version());
                try {
                    snapshots.recordSuccessful(candidate);
                    return runtime;
                } catch (RuntimeException e) {
                    runtime.close();
                    throw e;
                }
            } catch (RuntimeException | LinkageError e) {
                snapshots.recordFailed(candidate, e);
                aggregate.addSuppressed(e);
            }
        }
        throw aggregate;
    }

    static ManagedProtocolRuntime open(
            Path artifact,
            Path runtimeConfigDirectory,
            Logger logger,
            String pluginVersion) {
        return open(artifact, runtimeConfigDirectory, logger, pluginVersion,
                net.rafalohaki.veloauth.BuildConstants.EMBEDDED_VIAVERSION_VERSION);
    }

    private static ManagedProtocolRuntime open(
            Path artifact,
            Path runtimeConfigDirectory,
            Logger logger,
            String pluginVersion,
            String runtimeVersion) {
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
                return new ManagedProtocolRuntime(loader, delegate, runtimeVersion);
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
        invoke(inject, Objects.requireNonNull(channel, "channel"));
    }

    @Override
    public void sendVelocityForwardingRequest(
            Channel channel, int transactionId, Runnable loginContinuation) {
        invoke(sendVelocityForwardingRequest,
                Objects.requireNonNull(channel, "channel"),
                transactionId,
                Objects.requireNonNull(loginContinuation, "loginContinuation"));
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        RuntimeException failure = null;
        try {
            invoke(close);
        } catch (RuntimeException e) {
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
        if (failure != null) {
            throw failure;
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
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                input.transferTo(output);
                byte[] bytecode = output.toByteArray();
                return defineClass(name, bytecode, 0, bytecode.length);
            } catch (IOException e) {
                throw new ClassNotFoundException(name, e);
            }
        }
    }
}
