package com.example.encryptionexample;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES {
    private static final String ANDROID_KEY_STORE = KeyStore.getDefaultType();
    final String suchAlphabet = "abcdefghijklmnopqrstuvwxyz";

    KeyStore keyStore;

    public AES() {

        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void generateKey() {

        KeyGenParameterSpec aesSpec = new KeyGenParameterSpec.Builder("ALIAS", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setKeySize(128)
                .build();

        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            keyGenerator.init(aesSpec);
            keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void encrypt(){
        Cipher cipher;
        SecretKey secretKey;

        try {
        secretKey = ((KeyStore.SecretKeyEntry) keyStore.getEntry("ALIAS", null)).getSecretKey();
        cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        cipherOutputStream.write(suchAlphabet.getBytes());
            cipherOutputStream.flush();
            cipherOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void decrypt(){

        Cipher cipher;
        SecretKey secretKey;

        try{
            secretKey = ((KeyStore.SecretKeyEntry) keyStore.getEntry("ALIAS", null)).getSecretKey();
            cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

            IvParameterSpec ivParameterSpec = new IvParameterSpec(cipher.getIV());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            byte[] in = new byte[suchAlphabet.getBytes().length];
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
            CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
            IOUtils.readFully(cipherInputStream, in);
            cipherInputStream.close();

            String muchWow = new String(in);

            if (suchAlphabet.equals(muchWow)) {
                System.out.println("Working");
            } else {
                System.out.println("Not working");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
