package org.apz.manager.feature.backup

import android.content.Context
import android.content.pm.PackageManager
import android.system.Os
import org.apz.core.model.AppInfo
import org.apz.core.model.BackupInfo
import org.apz.manager.util.FileUtils
import org.apz.manager.util.SecurityUtils
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BackupManager(private val context: Context) {
    
    private val backupDir = File(context.getExternalFilesDir(null), "backups")
    private val tempDir = File(context.cacheDir, "backup_temp")
    
    init {
        backupDir.mkdirs()
        tempDir.mkdirs()
    }
    
    suspend fun createBackup(
        appInfo: AppInfo,
        includeData: Boolean = false,
        includeObb: Boolean = false,
        encrypt: Boolean = false
    ): BackupResult {
        return try {
            val timestamp = System.currentTimeMillis()
            val backupFileName = "${appInfo.packageName}_${timestamp}.apzb"
            val backupFile = File(backupDir, backupFileName)
            
            // ایجاد فایل ZIP برای بکاپ
            ZipOutputStream(FileOutputStream(backupFile)).use { zip ->
                // بکاپ APK اصلی
                backupApk(appInfo, zip)
                
                // بکاپ داده‌ها (در صورت درخواست و داشتن دسترسی)
                if (includeData && canAccessAppData()) {
                    backupAppData(appInfo, zip)
                }
                
                // بکاپ OBB (در صورت درخواست)
                if (includeObb) {
                    backupObbFiles(appInfo, zip)
                }
                
                // افزودن متادیتا
                addMetadata(appInfo, zip, includeData, includeObb, encrypt)
            }
            
            // رمزنگاری در صورت درخواست
            if (encrypt) {
                encryptBackup(backupFile)
            }
            
            val backupInfo = BackupInfo(
                packageName = appInfo.packageName,
                appName = appInfo.name,
                versionName = appInfo.versionName,
                versionCode = appInfo.versionCode,
                backupTime = timestamp,
                backupSize = backupFile.length(),
                backupPath = backupFile.absolutePath,
                includesData = includeData,
                includesObb = includeObb,
                isEncrypted = encrypt,
                signatureHash = appInfo.signature ?: ""
            )
            
            BackupResult.Success(backupInfo)
        } catch (e: Exception) {
            BackupResult.Error(e.message ?: "خطا در ایجاد بکاپ")
        }
    }
    
    suspend fun restoreBackup(backupInfo: BackupInfo): RestoreResult {
        return try {
            val backupFile = File(backupInfo.backupPath)
            if (!backupFile.exists()) {
                return RestoreResult.Error("فایل بکاپ یافت نشد")
            }
            
            // رمزگشایی در صورت نیاز
            val tempBackupFile = if (backupInfo.isEncrypted) {
                decryptBackup(backupFile) ?: return RestoreResult.Error("خطا در رمزگشایی")
            } else {
                backupFile
            }
            
            // استخراج و نصب
            val extractDir = File(tempDir, "restore_${System.currentTimeMillis()}")
            extractDir.mkdirs()
            
            FileUtils.extractZip(tempBackupFile, extractDir)
            
            // نصب APK
            val apkFile = File(extractDir, "base.apk")
            if (!apkFile.exists()) {
                return RestoreResult.Error("فایل APK در بکاپ یافت نشد")
            }
            
            // بازگردانی داده‌ها
            if (backupInfo.includesData && canAccessAppData()) {
                restoreAppData(extractDir, backupInfo.packageName)
            }
            
            // بازگردانی OBB
            if (backupInfo.includesObb) {
                restoreObbFiles(extractDir, backupInfo.packageName)
            }
            
            // تمیزکاری
            extractDir.deleteRecursively()
            if (backupInfo.isEncrypted) {
                tempBackupFile.delete()
            }
            
            RestoreResult.Success(backupInfo.packageName)
        } catch (e: Exception) {
            RestoreResult.Error(e.message ?: "خطا در بازگردانی بکاپ")
        }
    }
    
    fun getBackupList(): List<BackupInfo> {
        return backupDir.listFiles { file ->
            file.extension == "apzb"
        }?.mapNotNull { file ->
            parseBackupMetadata(file)
        } ?: emptyList()
    }
    
    fun deleteBackup(backupInfo: BackupInfo): Boolean {
        return try {
            File(backupInfo.backupPath).delete()
        } catch (e: Exception) {
            false
        }
    }
    
    private fun backupApk(appInfo: AppInfo, zip: ZipOutputStream) {
        val apkFile = File(appInfo.sourceDir)
        if (apkFile.exists()) {
            zip.putNextEntry(ZipEntry("base.apk"))
            FileInputStream(apkFile).use { input ->
                input.copyTo(zip)
            }
            zip.closeEntry()
        }
    }
    
    private fun backupAppData(appInfo: AppInfo, zip: ZipOutputStream) {
        val dataDir = File("/data/data/${appInfo.packageName}")
        if (dataDir.exists() && dataDir.canRead()) {
            zip.putNextEntry(ZipEntry("data/"))
            dataDir.walk().forEach { file ->
                if (file.isFile) {
                    val relativePath = file.relativeTo(dataDir).path
                    zip.putNextEntry(ZipEntry("data/$relativePath"))
                    FileInputStream(file).use { input ->
                        input.copyTo(zip)
                    }
                    zip.closeEntry()
                }
            }
        }
    }
    
    private fun backupObbFiles(appInfo: AppInfo, zip: ZipOutputStream) {
        val obbDir = File(context.obbDir, appInfo.packageName)
        if (obbDir.exists()) {
            obbDir.listFiles()?.forEach { obbFile ->
                zip.putNextEntry(ZipEntry("obb/${obbFile.name}"))
                FileInputStream(obbFile).use { input ->
                    input.copyTo(zip)
                }
                zip.closeEntry()
            }
        }
    }
    
    private fun addMetadata(
        appInfo: AppInfo,
        zip: ZipOutputStream,
        includeData: Boolean,
        includeObb: Boolean,
        encrypt: Boolean
    ) {
        val metadata = """
            package_name=${appInfo.packageName}
            app_name=${appInfo.name}
            version_name=${appInfo.versionName}
            version_code=${appInfo.versionCode}
            backup_time=${System.currentTimeMillis()}
            includes_data=$includeData
            includes_obb=$includeObb
            encrypted=$encrypt
            signature=${appInfo.signature}
        """.trimIndent()
        
        zip.putNextEntry(ZipEntry("metadata.ini"))
        zip.write(metadata.toByteArray())
        zip.closeEntry()
    }
    
    private fun parseBackupMetadata(file: File): BackupInfo? {
        return try {
            // استخراج متادیتا از فایل ZIP
            // (پیاده‌سازی ساده شده)
            BackupInfo(
                packageName = file.nameWithoutExtension.substringBefore("_"),
                appName = "",
                versionName = "",
                versionCode = 0,
                backupTime = file.lastModified(),
                backupSize = file.length(),
                backupPath = file.absolutePath,
                includesData = false,
                includesObb = false,
                isEncrypted = false,
                signatureHash = ""
            )
        } catch (e: Exception) {
            null
        }
    }
    
    private fun encryptBackup(backupFile: File): Boolean {
        return try {
            SecurityUtils.encryptFile(backupFile, context)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private fun decryptBackup(backupFile: File): File? {
        return try {
            SecurityUtils.decryptFile(backupFile, context)
        } catch (e: Exception) {
            null
        }
    }
    
    private fun canAccessAppData(): Boolean {
        return try {
            // بررسی دسترسی به داده‌های برنامه
            // (نیاز به دسترسی root یا Shizuku)
            Os.getuid() == 0 || context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_DEVICE_ADMIN
            )
        } catch (e: Exception) {
            false
        }
    }
    
    private fun restoreAppData(extractDir: File, packageName: String) {
        // پیاده‌سازی بازگردانی داده‌ها
    }
    
    private fun restoreObbFiles(extractDir: File, packageName: String) {
        // پیاده‌سازی بازگردانی فایل‌های OBB
    }
}

sealed class BackupResult {
    data class Success(val backupInfo: BackupInfo) : BackupResult()
    data class Error(val message: String) : BackupResult()
}

sealed class RestoreResult {
    data class Success(val packageName: String) : RestoreResult()
    data class Error(val message: String) : RestoreResult()
}