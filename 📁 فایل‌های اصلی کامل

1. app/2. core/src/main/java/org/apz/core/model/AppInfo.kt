package org.apz.core.model

import android.content.pm.PackageInfo
import android.graphics.drawable.Drawable
import kotlinx.parcelize.Parcelize
import android.os.Parcelable

@Parcelize
data class AppInfo(
    val packageName: String,
    val name: String,
    val versionName: String,
    val versionCode: Long,
    val icon: Drawable?,
    val installTime: Long,
    val updateTime: Long,
    val targetSdk: Int,
    val minSdk: Int,
    val permissions: List<String>,
    val requestedPermissions: List<String>,
    val activities: List<String>,
    val services: List<String>,
    val receivers: List<String>,
    val providers: List<String>,
    val signature: String?,
    val isSystemApp: Boolean,
    val isEnabled: Boolean,
    val sourceDir: String,
    val dataDir: String?,
    val size: Long,
    val cacheSize: Long,
    val dataSize: Long
) : Parcelable

@Parcelize
data class BackupInfo(
    val packageName: String,
    val appName: String,
    val versionName: String,
    val versionCode: Long,
    val backupTime: Long,
    val backupSize: Long,
    val backupPath: String,
    val includesData: Boolean,
    val includesObb: Boolean,
    val isEncrypted: Boolean,
    val signatureHash: String
) : Parcelable

enum class RiskLevel(val color: Int, val description: String) {
    LOW(0xFF4CAF50, "امن"),
    MEDIUM(0xFFFFC107, "متوسط"),
    HIGH(0xFFFF9800, "پرریسک"),
    CRITICAL(0xFFF44336, "خطرناک")
}

@Parcelize
data class SecurityScanResult(
    val riskLevel: RiskLevel,
    val score: Int,
    val warnings: List<SecurityWarning>,
    val recommendations: List<String>,
    val permissionAnalysis: PermissionAnalysis
) : Parcelable

@Parcelize
data class SecurityWarning(
    val type: WarningType,
    val title: String,
    val description: String,
    val severity: RiskLevel
) : Parcelable

@Parcelize
data class PermissionAnalysis(
    val dangerousPermissions: List<PermissionInfo>,
    val normalPermissions: List<PermissionInfo>,
    val signaturePermissions: List<PermissionInfo>,
    val unusualCombinations: List<String>
) : Parcelable

@Parcelize
data class PermissionInfo(
    val name: String,
    val group: String,
    val description: String,
    val risk: RiskLevel
) : Parcelable

enum class WarningType {
    DANGEROUS_PERMISSIONS,
    NETWORK_ACCESS,
    BACKGROUND_ACTIVITY,
    BOOT_COMPLETED,
    DEVICE_ADMIN,
    ACCESSIBILITY_SERVICE,
    UNUSUAL_COMBINATION,
    SUSPICIOUS_ACTIVITY
}