package net.rafalohaki.veloauth.dialog;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import net.kyori.adventure.nbt.BinaryTag;
import net.kyori.adventure.nbt.BinaryTagType;
import net.kyori.adventure.nbt.BinaryTagTypes;
import net.kyori.adventure.nbt.ByteBinaryTag;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import net.kyori.adventure.nbt.DoubleBinaryTag;
import net.kyori.adventure.nbt.EndBinaryTag;
import net.kyori.adventure.nbt.IntBinaryTag;
import net.kyori.adventure.nbt.ListBinaryTag;
import net.kyori.adventure.nbt.LongBinaryTag;
import net.kyori.adventure.nbt.StringBinaryTag;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.gson.GsonComponentSerializer;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds the NBT representation of Minecraft dialogs (the {@code minecraft:dialog} direct codec
 * introduced in 1.21.6 and unchanged through 26.3). Only the pieces VeloAuth needs are modelled:
 * {@code notice} and {@code confirmation} layouts, {@code plain_message} and {@code item} bodies,
 * {@code text} inputs and {@code dynamic/custom} click actions.
 *
 * <p>All text is serialized from Adventure components into the NBT text-component format, so
 * colors, decorations and translatable keys survive the trip to the client.
 */
public final class DialogNbt {

    /** Namespace of every custom click action emitted by VeloAuth dialogs. */
    public static final String ACTION_NAMESPACE = "veloauth";

    private static final GsonComponentSerializer GSON = GsonComponentSerializer.gson();

    private DialogNbt() {
    }

    // ------------------------------------------------------------------ public builders

    /** Fluent builder for a dialog compound. */
    public static DialogBuilder dialog(String type, Component title) {
        return new DialogBuilder(type, title);
    }

    /** A {@code minecraft:plain_message} body element. */
    public static CompoundBinaryTag plainMessage(Component text, int width) {
        return CompoundBinaryTag.builder()
                .putString("type", "minecraft:plain_message")
                .put("contents", component(text))
                .putInt("width", width)
                .build();
    }

    /** A {@code minecraft:item} body element with a description. */
    public static CompoundBinaryTag itemMessage(String itemId, Component description, int width) {
        CompoundBinaryTag item = CompoundBinaryTag.builder()
                .putString("id", itemId)
                .putInt("count", 1)
                .build();
        CompoundBinaryTag desc = CompoundBinaryTag.builder()
                .put("contents", component(description))
                .putInt("width", width)
                .build();
        return CompoundBinaryTag.builder()
                .putString("type", "minecraft:item")
                .put("item", item)
                .put("description", desc)
                .putBoolean("show_decorations", false)
                .putBoolean("show_tooltip", false)
                .putInt("width", 16)
                .putInt("height", 16)
                .build();
    }

    /** A single-line {@code minecraft:text} input. */
    public static CompoundBinaryTag textInput(String key, Component label, int maxLength, int width) {
        return CompoundBinaryTag.builder()
                .putString("type", "minecraft:text")
                .putString("key", key)
                .put("label", component(label))
                .putBoolean("label_visible", true)
                .putInt("width", width)
                .putString("initial", "")
                .putInt("max_length", maxLength)
                .build();
    }

    /**
     * A button whose click sends a {@code dynamic/custom} action (all input values plus the given
     * additions) to the proxy under {@code veloauth:<action>}.
     */
    public static CompoundBinaryTag customButton(Component label, String action, CompoundBinaryTag additions, int width) {
        CompoundBinaryTag.Builder click = CompoundBinaryTag.builder()
                .putString("type", "dynamic/custom")
                .putString("id", ACTION_NAMESPACE + ":" + action);
        if (additions != null && additions.size() > 0) {
            click.put("additions", additions);
        }
        return CompoundBinaryTag.builder()
                .put("label", component(label))
                .putInt("width", width)
                .put("action", click.build())
                .build();
    }

    /** A button with no action at all (e.g. a disabled-looking "please wait" button). */
    public static CompoundBinaryTag inertButton(Component label, int width) {
        return CompoundBinaryTag.builder()
                .put("label", component(label))
                .putInt("width", width)
                .build();
    }

    // ------------------------------------------------------------------ components -> NBT

    /** Serializes an Adventure component into the NBT text-component form. */
    public static BinaryTag component(Component component) {
        return fromJson(GSON.serializeToTree(component));
    }

    /**
     * Converts a JSON tree into NBT the same way the vanilla client does for text components
     * (booleans become bytes, heterogeneous lists are wrapped into compounds under {@code ""}).
     */
    public static BinaryTag fromJson(JsonElement json) {
        if (json == null || json.isJsonNull()) {
            return EndBinaryTag.endBinaryTag();
        }
        if (json instanceof JsonPrimitive primitive) {
            return fromPrimitive(primitive);
        }
        if (json instanceof JsonObject object) {
            return fromObject(object);
        }
        if (json instanceof JsonArray array) {
            return fromArray(array);
        }
        return EndBinaryTag.endBinaryTag();
    }

    private static BinaryTag fromPrimitive(JsonPrimitive primitive) {
        if (primitive.isBoolean()) {
            return ByteBinaryTag.byteBinaryTag((byte) (primitive.getAsBoolean() ? 1 : 0));
        }
        if (primitive.isString()) {
            return StringBinaryTag.stringBinaryTag(primitive.getAsString());
        }
        return fromNumber(primitive.getAsNumber());
    }

    private static BinaryTag fromNumber(Number number) {
        if (number instanceof Long) {
            return LongBinaryTag.longBinaryTag(number.longValue());
        }
        if (number instanceof Double || number instanceof Float || looksFractional(number.toString())) {
            return DoubleBinaryTag.doubleBinaryTag(number.doubleValue());
        }
        long value = number.longValue();
        return value < Integer.MIN_VALUE || value > Integer.MAX_VALUE
                ? LongBinaryTag.longBinaryTag(value)
                : IntBinaryTag.intBinaryTag((int) value);
    }

    private static boolean looksFractional(String raw) {
        return raw.contains(".") || raw.contains("e") || raw.contains("E");
    }

    private static BinaryTag fromObject(JsonObject object) {
        CompoundBinaryTag.Builder compound = CompoundBinaryTag.builder();
        for (var entry : object.entrySet()) {
            BinaryTag value = fromJson(entry.getValue());
            if (value.type() != BinaryTagTypes.END) {
                compound.put(entry.getKey(), value);
            }
        }
        return compound.build();
    }

    // BinaryTagType constants are singletons; identity is the documented comparison. Calling
    // methods (equals) on a BinaryTagType reference is deliberately avoided because the type is
    // an abstract class in Adventure 4.x and an interface in Adventure 5.x.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    private static BinaryTag fromArray(JsonArray array) {
        if (array.isEmpty()) {
            return ListBinaryTag.empty();
        }
        List<BinaryTag> items = new ArrayList<>(array.size());
        BinaryTagType<? extends BinaryTag> listType = null;
        for (JsonElement element : array) {
            BinaryTag tag = fromJson(element);
            items.add(tag);
            if (listType == null) {
                listType = tag.type();
            } else if (listType != tag.type()) {
                listType = BinaryTagTypes.COMPOUND;
            }
        }
        if (listType == BinaryTagTypes.COMPOUND) {
            items.replaceAll(tag -> tag.type() == BinaryTagTypes.COMPOUND
                    ? tag
                    : CompoundBinaryTag.builder().put("", tag).build());
        }
        return ListBinaryTag.listBinaryTag(listType, items);
    }

    // ------------------------------------------------------------------ builder

    /** Builder for the common dialog fields plus the layout-specific buttons. */
    public static final class DialogBuilder {
        private final CompoundBinaryTag.Builder root = CompoundBinaryTag.builder();
        private final List<BinaryTag> body = new ArrayList<>();
        private final List<BinaryTag> inputs = new ArrayList<>();

        private DialogBuilder(String type, Component title) {
            root.putString("type", type);
            root.put("title", component(title));
            root.put("external_title", component(title));
            root.putBoolean("can_close_with_escape", false);
            root.putBoolean("pause", false);
            root.putString("after_action", "wait_for_response");
        }

        /** Overrides {@code after_action} ({@code close}, {@code none}, {@code wait_for_response}). */
        public DialogBuilder afterAction(String afterAction) {
            root.putString("after_action", afterAction);
            return this;
        }

        public DialogBuilder closableWithEscape(boolean value) {
            root.putBoolean("can_close_with_escape", value);
            return this;
        }

        public DialogBuilder body(CompoundBinaryTag element) {
            body.add(element);
            return this;
        }

        public DialogBuilder input(CompoundBinaryTag element) {
            inputs.add(element);
            return this;
        }

        /** Layout {@code minecraft:confirmation}: two footer buttons. */
        public DialogBuilder confirmation(CompoundBinaryTag yes, CompoundBinaryTag no) {
            root.put("yes", yes);
            root.put("no", no);
            return this;
        }

        /** Layout {@code minecraft:notice}: one footer button. */
        public DialogBuilder notice(CompoundBinaryTag action) {
            root.put("action", action);
            return this;
        }

        /** Layout {@code minecraft:multi_action}: a button grid plus optional exit button. */
        public DialogBuilder multiAction(List<CompoundBinaryTag> actions, int columns, CompoundBinaryTag exit) {
            root.put("actions", ListBinaryTag.listBinaryTag(BinaryTagTypes.COMPOUND, new ArrayList<>(actions)));
            root.putInt("columns", columns);
            if (exit != null) {
                root.put("exit_action", exit);
            }
            return this;
        }

        public CompoundBinaryTag build() {
            if (!body.isEmpty()) {
                root.put("body", ListBinaryTag.listBinaryTag(BinaryTagTypes.COMPOUND, body));
            }
            if (!inputs.isEmpty()) {
                root.put("inputs", ListBinaryTag.listBinaryTag(BinaryTagTypes.COMPOUND, inputs));
            }
            return root.build();
        }
    }
}
