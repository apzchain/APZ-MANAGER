package org.apz.manager.feature.install

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.core.content.FileProvider
import org.apz.core.model.SecurityScanResult
import org.apz.manager.util.FileUtils
import org.apz.manager.feature.security.SecurityAnalyzer
import java.io.File

class Installer(private val context: Context) {
    
    private val securityAnalyzer = SecurityAnalyzer(context)
    
    suspend fun installApk(apkFile: File): InstallResult {
        return try {
            // تحلیل امنیتی APK
            val securityScan = securityAnalyzer.analyzeApk(apkFile)
            
            // نصب APK
            val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    FileProvider.getUriForFile(
                        context,
                        "${context.packageName}.provider",
                        apkFile
                    )
                } else {
                    Uri.fromFile(apkFile)
                }
                
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                putExtra(Intent.EXTRA_NOT_UNKNOWN_SOURCE, true)
                putExtra(Intent.EXTRA_RETURN_RESULT, true)
            }
            
            InstallResult.Success(securityScan, intent)
        } catch (e: Exception) {
            InstallResult.Error(e.message ?: "خطا در نصب APK")
        }
    }
    
    fun uninstallApp(packageName: String): Boolean {
        return try {
            val intent = Intent(Intent.ACTION_DELETE).apply {
                data = Uri.parse("package:$packageName")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    @Composable
    fun rememberInstallLauncher(
        onSuccess: (String) -> Unit,
        onError: (String) -> Unit
    ) = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            onSuccess("نصب با موفقیت انجام شد")
        } else {
            onError("خطا در نصب برنامه")
        }
    }
}

sealed class InstallResult {
    data class Success(
        val securityScan: SecurityScanResult,
        val installIntent: Intent
    ) : InstallResult()
    
    data class Error(val message: String) : InstallResult()
}