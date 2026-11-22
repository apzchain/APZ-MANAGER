package org.apz.manager.feature.security

import android.content.Context
import android.content.pm.PackageManager
import net.dongliu.apk.parser.ApkFile
import net.dongliu.apk.parser.bean.ApkMeta
import org.apz.core.model.*
import org.apz.core.constants.PermissionGroups
import java.io.File

class SecurityAnalyzer(private val context: Context) {
    
    suspend fun analyzeApk(apkFile: File): SecurityScanResult {
        return try {
            ApkFile(apkFile).use { apk ->
                val meta = apk.apkMeta
                val manifest = apk.manifest
                
                // تحلیل مجوزها
                val permissionAnalysis = analyzePermissions(meta.usesPermissions)
                
                // تشخیص خطرات
                val warnings = detectWarnings(meta, permissionAnalysis)
                
                // محاسبه امتیاز ریسک
                val riskScore = calculateRiskScore(warnings, permissionAnalysis)
                val riskLevel = determineRiskLevel(riskScore)
                
                SecurityScanResult(
                    riskLevel = riskLevel,
                    score = riskScore,
                    warnings = warnings,
                    recommendations = generateRecommendations(warnings),
                    permissionAnalysis = permissionAnalysis
                )
            }
        } catch (e: Exception) {
            // تحلیل پایه در صورت خطا
            SecurityScanResult(
                riskLevel = RiskLevel.MEDIUM,
                score = 50,
                warnings = listOf(
                    SecurityWarning(
                        type = WarningType.SUSPICIOUS_ACTIVITY,
                        title = "خطا در تحلیل امنیتی",
                        description = "امکان تحلیل کامل APK وجود ندارد",
                        severity = RiskLevel.MEDIUM
                    )
                ),
                recommendations = listOf("این فایل را از منابع معتبر دریافت کنید"),
                permissionAnalysis = PermissionAnalysis(
                    dangerousPermissions = emptyList(),
                    normalPermissions = emptyList(),
                    signaturePermissions = emptyList(),
                    unusualCombinations = emptyList()
                )
            )
        }
    }
    
    fun analyzeInstalledApp(packageName: String): SecurityScanResult {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                packageName, 
                PackageManager.GET_PERMISSIONS or 
                PackageManager.GET_SIGNATURES
            )
            
            val permissions = packageInfo.requestedPermissions ?: emptyArray()
            val permissionAnalysis = analyzePermissions(permissions.toList())
            
            val warnings = detectInstalledAppWarnings(packageInfo, permissionAnalysis)
            val riskScore = calculateRiskScore(warnings, permissionAnalysis)
            val riskLevel = determineRiskLevel(riskScore)
            
            SecurityScanResult(
                riskLevel = riskLevel,
                score = riskScore,
                warnings = warnings,
                recommendations = generateRecommendations(warnings),
                permissionAnalysis = permissionAnalysis
            )
        } catch (e: Exception) {
            SecurityScanResult(
                riskLevel = RiskLevel.MEDIUM,
                score = 50,
                warnings = emptyList(),
                recommendations = emptyList(),
                permissionAnalysis = PermissionAnalysis(
                    dangerousPermissions = emptyList(),
                    normalPermissions = emptyList(),
                    signaturePermissions = emptyList(),
                    unusualCombinations = emptyList()
                )
            )
        }
    }
    
    private fun analyzePermissions(permissions: List<String>): PermissionAnalysis {
        val dangerous = mutableListOf<PermissionInfo>()
        val normal = mutableListOf<PermissionInfo>()
        val signature = mutableListOf<PermissionInfo>()
        
        permissions.forEach { permission ->
            val permissionInfo = getPermissionInfo(permission)
            when {
                PermissionGroups.DANGEROUS_PERMISSIONS.any { 
                    permission.startsWith(it) 
                } -> dangerous.add(permissionInfo)
                PermissionGroups.SIGNATURE_PERMISSIONS.any { 
                    permission.startsWith(it) 
                } -> signature.add(permissionInfo)
                else -> normal.add(permissionInfo)
            }
        }
        
        return PermissionAnalysis(
            dangerousPermissions = dangerous,
            normalPermissions = normal,
            signaturePermissions = signature,
            unusualCombinations = detectUnusualCombinations(dangerous)
        )
    }
    
    private fun getPermissionInfo(permission: String): PermissionInfo {
        val group = permission.substringBeforeLast('.')
        val description = getPermissionDescription(permission)
        val risk = when {
            PermissionGroups.DANGEROUS_PERMISSIONS.any { 
                permission.startsWith(it) 
            } -> RiskLevel.HIGH
            PermissionGroups.SIGNATURE_PERMISSIONS.any { 
                permission.startsWith(it) 
            } -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
        
        return PermissionInfo(permission, group, description, risk)
    }
    
    private fun getPermissionDescription(permission: String): String {
        return when {
            permission.contains("READ_EXTERNAL_STORAGE") -> "دسترسی به حافظه خارجی"
            permission.contains("ACCESS_FINE_LOCATION") -> "دسترسی به موقعیت دقیق"
            permission.contains("CAMERA") -> "دسترسی به دوربین"
            permission.contains("RECORD_AUDIO") -> "ضبط صدا"
            permission.contains("READ_CONTACTS") -> "خواندن مخاطبین"
            permission.contains("READ_SMS") -> "خواندن پیامک‌ها"
            else -> "مجوز سیستم"
        }
    }
    
    private fun detectWarnings(
        meta: ApkMeta,
        permissionAnalysis: PermissionAnalysis
    ): List<SecurityWarning> {
        val warnings = mutableListOf<SecurityWarning>()
        
        // بررسی مجوزهای خطرناک
        if (permissionAnalysis.dangerousPermissions.size > 5) {
            warnings.add(
                SecurityWarning(
                    type = WarningType.DANGEROUS_PERMISSIONS,
                    title = "مجوزهای خطرناک زیاد",
                    description = "این برنامه به تعداد زیادی مجوز خطرناک دسترسی دارد",
                    severity = RiskLevel.HIGH
                )
            )
        }
        
        // بررسی دسترسی به شبکه
        if (permissionAnalysis.dangerousPermissions.any { 
            it.name.contains("INTERNET") 
        }) {
            warnings.add(
                SecurityWarning(
                    type = WarningType.NETWORK_ACCESS,
                    title = "دسترسی به اینترنت",
                    description = "این برنامه می‌تواند به اینترنت متصل شود",
                    severity = RiskLevel.MEDIUM
                )
            )
        }
        
        return warnings
    }
    
    private fun detectInstalledAppWarnings(
        packageInfo: android.content.pm.PackageInfo,
        permissionAnalysis: PermissionAnalysis
    ): List<SecurityWarning> {
        // پیاده‌سازی مشابه برای اپ‌های نصب شده
        return detectWarnings(
            ApkMeta().apply {
                packageName = packageInfo.packageName
            },
            permissionAnalysis
        )
    }
    
    private fun calculateRiskScore(
        warnings: List<SecurityWarning>,
        permissionAnalysis: PermissionAnalysis
    ): Int {
        var score = 0
        
        // امتیاز بر اساس تعداد هشدارها
        warnings.forEach { warning ->
            score += when (warning.severity) {
                RiskLevel.LOW -> 5
                RiskLevel.MEDIUM -> 15
                RiskLevel.HIGH -> 30
                RiskLevel.CRITICAL -> 50
            }
        }
        
        // امتیاز بر اساس مجوزهای خطرناک
        score += permissionAnalysis.dangerousPermissions.size * 10
        
        return score.coerceIn(0, 100)
    }
    
    private fun determineRiskLevel(score: Int): RiskLevel {
        return when {
            score < 20 -> RiskLevel.LOW
            score < 50 -> RiskLevel.MEDIUM
            score < 80 -> RiskLevel.HIGH
            else -> RiskLevel.CRITICAL
        }
    }
    
    private fun detectUnusualCombinations(
        dangerousPermissions: List<PermissionInfo>
    ): List<String> {
        val combinations = mutableListOf<String>()
        
        val hasLocation = dangerousPermissions.any { 
            it.name.contains("LOCATION") 
        }
        val hasCamera = dangerousPermissions.any { 
            it.name.contains("CAMERA") 
        }
        val hasMicrophone = dangerousPermissions.any { 
            it.name.contains("RECORD_AUDIO") 
        }
        
        if (hasLocation && hasCamera && hasMicrophone) {
            combinations.add("دسترسی همزمان به موقعیت، دوربین و میکروفون")
        }
        
        return combinations
    }
    
    private fun generateRecommendations(warnings: List<SecurityWarning>): List<String> {
        val recommendations = mutableListOf<String>()
        
        if (warnings.any { it.severity == RiskLevel.HIGH }) {
            recommendations.add("قبل از نصب، مجوزها را به دقت بررسی کنید")
        }
        
        if (warnings.any { it.type == WarningType.NETWORK_ACCESS }) {
            recommendations.add("دسترسی اینترنتی برنامه را کنترل کنید")
        }
        
        return recommendations
    }
}