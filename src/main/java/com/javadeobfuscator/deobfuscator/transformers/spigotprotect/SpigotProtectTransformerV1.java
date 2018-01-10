/*
 * Copyright 2018 Sam Sun <github-contact@samczsun.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.javadeobfuscator.deobfuscator.transformers.spigotprotect;

import com.javadeobfuscator.deobfuscator.config.*;
import com.javadeobfuscator.deobfuscator.exceptions.*;
import com.javadeobfuscator.deobfuscator.transformers.*;
import com.javadeobfuscator.deobfuscator.transformers.zelix.string.*;
import com.javadeobfuscator.deobfuscator.utils.*;
import com.javadeobfuscator.javavm.utils.*;
import org.apache.commons.lang3.*;
import org.objectweb.asm.tree.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;

/**
 * "JavaDeobfuscator often crashes, or results in weird messed up non-readable code" you say?!?!
 */
public class SpigotProtectTransformerV1 extends Transformer<TransformerConfig> {
    @Override
    public boolean transform() throws Throwable, WrongTransformerException {
        if (classes.size() != 1) {
            oops("expected only one class");
            return false;
        }

        EnhancedStringEncryptionTransformer.Config config = (EnhancedStringEncryptionTransformer.Config) TransformerConfig.configFor(EnhancedStringEncryptionTransformer.class);
        config.setSlowlyDetermineMagicNumbers(true);
        getDeobfuscator().runFromConfig(config);

        ClassNode target = classes.values().iterator().next();
        MethodNode onEnable = ASMHelper.findMethod(target, "onEnable", "()V");
        if (onEnable == null) {
            oops("expected onEnable");
            return false;
        }

        Set<String> md5Magic = new HashSet<>();
        Set<String> aesMagic1 = new HashSet<>();
        Set<String> aesMagic2 = new HashSet<>();
        Set<String> aesMagic3 = new HashSet<>();

        // Find the magic values using the most hacky code ever
        for (AbstractInsnNode insn : TransformerHelper.instructionIterator(onEnable)) {
            if (insn.getOpcode() != LDC) continue;

            LdcInsnNode ldcInsnNode = (LdcInsnNode) insn;
            if (!(ldcInsnNode.cst instanceof String)) continue;

            String cst = (String) ldcInsnNode.cst;
            // filter out obvious bad keys
            if (!cst.toLowerCase().equals(cst)) continue;
            if (!cst.replaceAll("[^a-z0-9]", "").equals(cst)) continue;

            if (cst.length() == 16) {
                md5Magic.add(cst);
            } else if (cst.length() == 1) {
                aesMagic3.add(cst);
            } else if (cst.length() == 3) {
                aesMagic2.add(cst);
            } else if (cst.length() == 10) {
                aesMagic1.add(cst);
            }
        }

        logger.debug("found magic values {} {} {} {}", md5Magic, aesMagic1, aesMagic2, aesMagic3);

        if (md5Magic.isEmpty() || aesMagic1.isEmpty() || aesMagic2.isEmpty() || aesMagic3.isEmpty())
            throw new WrongTransformerException("missing magic values");

        Set<String> keys = new HashSet<>();

        // Construct possible keys
        for (String aes1 : aesMagic1) {
            for (String aes2 : aesMagic2) {
                for (String aes3 : aesMagic3) {
                    keys.add(aes1 + "w" + aes2 + "!" + aes3);
                }
            }
        }


        Cipher desCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        MessageDigest md5Digest = MessageDigest.getInstance("md5");

        Map<String, byte[]> decrypted = new HashMap<>();

        for (Map.Entry<String, byte[]> passthrough : getDeobfuscator().getInputPassthrough().entrySet()) {
            if (!passthrough.getKey().endsWith(".meow")) continue;

            byte[] encrypted = passthrough.getValue();

            for (int i = 0, j = 68; i < j; i++, j--) {
                ArrayUtils.swap(encrypted, i, j);
            }
            for (int i = 69, j = encrypted.length - 1; i < j; i++, j--) {
                ArrayUtils.swap(encrypted, i, j);
            }
            for (int i = 0, j = encrypted.length - 1; i < j; i++, j--) {
                ArrayUtils.swap(encrypted, i, j);
            }

            byte[] desDec = null;
            for (Iterator<String> md5Iterator = md5Magic.iterator(); md5Iterator.hasNext(); ) {
                String magic = md5Iterator.next();
                desDec = Arrays.copyOf(encrypted, encrypted.length);

                try {
                    for (int iter = 0; iter < 6; iter++) {
                        byte[] bytes = Arrays.copyOf(md5Digest.digest(magic.getBytes()), 24);
                        System.arraycopy(bytes, 0, bytes, 16, 8);
                        SecretKeySpec desKeySpec = new SecretKeySpec(bytes, "DESede");
                        IvParameterSpec desIvSpec = new IvParameterSpec(new byte[8]);
                        desCipher.init(Cipher.DECRYPT_MODE, desKeySpec, desIvSpec);
                        desDec = desCipher.doFinal(desDec);
                    }
                } catch (GeneralSecurityException ex) {
                    logger.debug("failed md5 magic {}", magic);
                    md5Iterator.remove();
                }
            }

            if (desDec == null) {
                oops("no md5 magic values found");
                return false;
            }

            desDec = Base64.getUrlDecoder().decode(desDec);

            byte[] aesDec = null;
            for (Iterator<String> aesIterator = keys.iterator(); aesIterator.hasNext(); ) {
                String aesKey = aesIterator.next();

                aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey.getBytes(), "AES"));
                try {
                    aesDec = aesCipher.doFinal(desDec);
                } catch (GeneralSecurityException ex) {
                    logger.debug("failed aes key {}", aesKey);
                    aesIterator.remove();
                }
            }

            if (aesDec == null) {
                oops("no aes magic values found");
                return false;
            }

            decrypted.put(passthrough.getKey(), aesDec);
        }

        // Do cleanup

        // Load decrypted classes
        for (Map.Entry<String, byte[]> entry : decrypted.entrySet()) {
            String modifiedName = entry.getKey().replace(".meow", ".class");
            logger.info("Decrypted class {} -> {}", entry.getKey(), modifiedName);
            getDeobfuscator().getInputPassthrough().remove(entry.getKey());
            getDeobfuscator().loadInput(modifiedName, entry.getValue());
        }

        // Remove loader class
        getDeobfuscator().getClasses().remove(target.name);

        // Restore plugin.yml
        String main = new String(getDeobfuscator().getInputPassthrough().get("META-INF/main.catz")).substring("main=".length());
        String pluginyml = new String(getDeobfuscator().getInputPassthrough().get("plugin.yml"), StandardCharsets.UTF_8);
        pluginyml = pluginyml.replace(target.name, main);
        getDeobfuscator().getInputPassthrough().put("plugin.yml", pluginyml.getBytes(StandardCharsets.UTF_8));

        // Remove META-INF files
        getDeobfuscator().getInputPassthrough().remove("META-INF/integrity.catz");
        getDeobfuscator().getInputPassthrough().remove("META-INF/main.catz");
        getDeobfuscator().getInputPassthrough().remove("META-INF/meow.catz");

        return !decrypted.isEmpty();
    }
}
