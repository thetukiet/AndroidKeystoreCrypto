package com.my.cryptolib;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecureKey {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "YOUR_SECURE_KEY";

    public byte[] encryptText(final String textToEncrypt) {
        try {
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(KEY_ALIAS));

            byte[] iv = cipher.getIV();
            byte[] encryptedBytes = cipher.doFinal(textToEncrypt.getBytes("UTF-8"));
            return getCombinedArray(iv, encryptedBytes);

        } catch (Exception ex){
            ex.printStackTrace();
            return null;
        }
    }

    private SecretKey getSecretKey(final String alias) {
        try {
            final KeyGenerator keyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

            keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());

            return keyGenerator.generateKey();
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }


    public String decryptData(final byte[] combinedEncryptedBytes) {
        try {
            DecombineByteArrayInfo arraysInfo  = decombineArray(combinedEncryptedBytes, 12);
            byte[] encryptedData = arraysInfo.getTwo();
            byte[] encryptionIv = arraysInfo.getOne();

            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(keyStore, KEY_ALIAS), spec);

            return new String(cipher.doFinal(encryptedData), "UTF-8");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private SecretKey getSecretKey(KeyStore keyStore, final String alias) {
        try {
            return ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null)).getSecretKey();
        } catch (Exception ex){
            ex.printStackTrace();
            return null;
        }
    }

    private static byte[] getCombinedArray(byte[] one, byte[] two) {
        byte[] combined = new byte[one.length + two.length];
        for (int i = 0; i < combined.length; ++i) {
            combined[i] = i < one.length ? one[i] : two[i - one.length];
        }
        return combined;
    }

    private static DecombineByteArrayInfo decombineArray(byte[] combined, int oneLength) {
        byte[] two = new byte[combined.length - oneLength];
        byte[] one = new byte[oneLength];

        for (int i = 0; i < combined.length; ++i) {
            if(i<oneLength)
                one[i] = combined[i];
            else
                two[i - oneLength] = combined[i];
        }
        return new DecombineByteArrayInfo(one, two);
    }

    static class DecombineByteArrayInfo{
        private byte[] one;
        private byte[] two;

        DecombineByteArrayInfo(byte[] one, byte[]two){
            this.one = one;
            this.two = two;
        }
        public byte[] getOne() {
            return one;
        }

        public byte[] getTwo() {
            return two;
        }
    }
}
