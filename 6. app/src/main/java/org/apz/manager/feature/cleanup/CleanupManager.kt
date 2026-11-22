package org.apz.manager.feature.cleanup

import android.content.Context
import android.content.pm.PackageManager
import org.apz.core.model.AppInfo
import java.io.File

class CleanupManager(private val context: Context) {
    
    data class CleanupResult(
        val totalSpaceFreed: Long,
        val cacheCleared: Int,
        val residualFilesDeleted: Int,
        val largeFilesDeleted: Int
    )
    
    suspend fun scanForCleanup(): CleanupScanResult {
        val largeFiles = scanLargeFiles()
        val cacheFiles = scanCacheFiles()
        val residualFiles = scanResidualFiles()
        
        return CleanupScanResult(
            largeFiles = largeFiles,
            cacheFiles = cacheFiles,
            residualFiles = residualFiles,
            totalCleanableSize = largeFiles.sumOf { it.size } + 
                               cacheFiles.sumOf { it.size } + 
                               residualFiles.sumOf { it.size }
        )
    }
    
    suspend fun performCleanup(scanResult: CleanupScanResult): CleanupResult {
        var spaceFreed = 0L
        var cacheCount = 0
        var residualCount = 0
        var largeFileCount = 0
        
        // پاکسازی کش‌ها
        scanResult.cacheFiles.forEach { file ->
            if (file.delete() || deleteFileRecursively(file)) {
                spaceFreed += file.length()
                cacheCount++
            }
        }
        
        // پاکسازی فایل‌های باقیمانده
        scanResult.residualFiles.forEach { file ->
            if (file.delete() || deleteFileRecursively(file)) {
                spaceFreed += file.length()
                residualCount++
            }
        }
        
        // پاکسازی فایل‌های بزرگ (با تأیید کاربر)
        scanResult.largeFiles.forEach { file ->
            if (file.delete() || deleteFileRecursively(file)) {
                spaceFreed += file.length()
                largeFileCount++
            }
        }
        
        return CleanupResult(
            totalSpaceFreed = spaceFreed,
            cacheCleared = cacheCount,
            residualFilesDeleted = residualCount,
            largeFilesDeleted = largeFileCount
        )
    }
    
    fun clearAppCache(packageName: String): Boolean {
        return try {
            val packageManager = context.packageManager
            val applicationInfo = packageManager.getApplicationInfo(packageName, 0)
            val cacheDir = File(applicationInfo.dataDir, "cache")
            
            if (cacheDir.exists()) {
                deleteFileRecursively(cacheDir)
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
    
    private fun scanLargeFiles(): List<File> {
        val largeFiles = mutableListOf<File>()
        val storageDir = context.getExternalFilesDir(null)?.parentFile ?: return emptyList()
        
        storageDir.walk()
            .filter { it.isFile && it.length() > 50 * 1024 * 1024 } // فایل‌های بزرگتر از 50MB
            .forEach { largeFiles.add(it) }
        
        return largeFiles
    }
    
    private fun scanCacheFiles(): List<File> {
        val cacheFiles = mutableListOf<File>()
        
        // اسکن کش برنامه‌های کاربر
        context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            .forEach { appInfo ->
                val cacheDir = File(appInfo.dataDir, "cache")
                if (cacheDir.exists()) {
                    cacheDir.walk()
                        .filter { it.isFile }
                        .forEach { cacheFiles.add(it) }
                }
            }
        
        return cacheFiles
    }
    
    private fun scanResidualFiles(): List<File> {
        val residualFiles = mutableListOf<File>()
        val downloadDir = File(context.getExternalFilesDir(null)?.parentFile, "Download")
        
        // فایل‌های APK قدیمی
        downloadDir.walk()
            .filter { it.isFile && it.extension.equals("apk", ignoreCase = true) }
            .forEach { residualFiles.add(it) }
        
        // فایل‌های موقت
        val tempDir = File(context.cacheDir, "temp")
        if (tempDir.exists()) {
            tempDir.walk()
                .filter { it.isFile }
                .forEach { residualFiles.add(it) }
        }
        
        return residualFiles
    }
    
    private fun deleteFileRecursively(file: File): Boolean {
        return if (file.isDirectory) {
            file.listFiles()?.all { deleteFileRecursively(it) } == true && file.delete()
        } else {
            file.delete()
        }
    }
}

data class CleanupScanResult(
    val largeFiles: List<File>,
    val cacheFiles: List<File>,
    val residualFiles: List<File>,
    val totalCleanableSize: Long
)