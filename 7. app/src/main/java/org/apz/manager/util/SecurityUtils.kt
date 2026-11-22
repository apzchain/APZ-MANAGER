package org.apz.manager.util

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object SecurityUtils {
    private const val KEY_ALIAS = "apz_backup_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    
    fun encryptFile(file: File, context: Context): Boolean {
        return try {
            val cipher = getCipher()
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            
            val iv = cipher.iv
            val encryptedData = cipher.doFinal(file.readBytes())
            
            // ذخیره IV و داده رمز شده
            val outputFile = File(file.parent, "${file.name}.enc")
            outputFile.writeBytes(iv + encryptedData)
            
            // حذف فایل اصلی
            file.delete()
            
            true
        } catch (e: Exception) {
            false
        }
    }
    
    fun decryptFile(encryptedFile: File, context: Context): File? {
        return try {
            val encryptedData = encryptedFile.readBytes()
            val iv = encryptedData.copyOfRange(0, 12) // IV 12 بایت
            val data = encryptedData.copyOfRange(12, encryptedData.size)
            
            val cipher = getCipher()
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            
            val decryptedData = cipher.doFinal(data)
            
            val outputFile = File(encryptedFile.parent, encryptedFile.nameWithoutExtension)
            outputFile.writeBytes(decryptedData)
            
            outputFile
        } catch (e: Exception) {
            null
        }
    }
    
    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, 
                ANDROID_KEYSTORE
            )
            
            val keyGenSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            
            keyGenerator.init(keyGenSpec)
            keyGenerator.generateKey()
        }
        
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
    }
    
    private fun getCipher(): Cipher {
        return Cipher.getInstance(TRANSFORMATION)
    }
    
    fun calculateFileHash(file: File): String {
        return try {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            Base64.encodeToString(digest.digest(), Base64.NO_WRAP)
        } catch (e: Exception) {
            ""
        }
    }
}