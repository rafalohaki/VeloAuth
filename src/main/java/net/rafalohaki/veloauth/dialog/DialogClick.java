package net.rafalohaki.veloauth.dialog;

import net.kyori.adventure.nbt.BinaryTag;
import net.kyori.adventure.nbt.BinaryTagTypes;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import net.kyori.adventure.nbt.StringBinaryTag;

/**
 * A custom click action received from the client for one of VeloAuth's dialogs.
 *
 * @param action  the action path, i.e. the part after {@code veloauth:}
 * @param payload the submitted inputs (plus button additions); empty compound when absent
 */
public record DialogClick(String action, CompoundBinaryTag payload) {

    /** Returns the submitted text for the given input key, or {@code null} when absent. */
    public String text(String key) {
        BinaryTag tag = payload.get(key);
        if (tag == null) {
            return null;
        }
        if (tag.type() == BinaryTagTypes.STRING) {
            return ((StringBinaryTag) tag).value();
        }
        return tag.toString();
    }
}
