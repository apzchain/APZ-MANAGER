package org.apz.manager.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import org.apz.core.model.RiskLevel
import org.apz.manager.feature.details.AppDetailsViewModel
import org.apz.manager.ui.components.PermissionAnalysisCard
import org.apz.manager.ui.components.RiskIndicator
import org.apz.manager.ui.components.SecurityWarningDialog

@Composable
fun AppDetailsScreen(
    packageName: String,
    onBack: () -> Unit,
    viewModel: AppDetailsViewModel = viewModel()
) {
    val appInfo by viewModel.appInfo.collectAsState()
    val securityScan by viewModel.securityScan.collectAsState()
    val showSecurityDialog = remember { mutableStateOf(false) }
    
    LaunchedEffect(packageName) {
        viewModel.loadAppDetails(packageName)
        viewModel.analyzeSecurity(packageName)
    }
    
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("جزئیات برنامه") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "بازگشت")
                    }
                },
                actions = {
                    IconButton(onClick = { 
                        viewModel.createBackup(includeData = true) 
                    }) {
                        Icon(Icons.Default.Backup, contentDescription = "بکاپ")
                    }
                    IconButton(onClick = { 
                        viewModel.uninstallApp(packageName) 
                    }) {
                        Icon(Icons.Default.Delete, contentDescription = "حذف")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
        ) {
            appInfo?.let { app ->
                // هدر برنامه
                AppHeaderSection(app, securityScan)
                
                // اطلاعات پایه
                AppInfoSection(app)
                
                // تحلیل امنیتی
                SecurityAnalysisSection(
                    securityScan = securityScan,
                    onShowDetails = { showSecurityDialog.value = true }
                )
                
                // مجوزها
                securityScan?.permissionAnalysis?.let { permissions ->
                    PermissionAnalysisCard(
                        permissionAnalysis = permissions,
                        modifier = Modifier.padding(16.dp)
                    )
                }
                
                // اقدامات
                ActionSection(
                    onBackup = { viewModel.createBackup() },
                    onClearCache = { viewModel.clearAppCache() },
                    onAnalyze = { viewModel.analyzeSecurity(packageName) }
                )
            }
        }
    }
    
    // دیالوگ امنیتی
    if (showSecurityDialog.value) {
        securityScan?.let { scan ->
            SecurityWarningDialog(
                securityScan = scan,
                onDismiss = { showSecurityDialog.value = false }
            )
        }
    }
}

@Composable
private fun AppHeaderSection(
    appInfo: org.apz.core.model.AppInfo,
    securityScan: org.apz.core.model.SecurityScanResult?
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        elevation = CardDefaults.cardElevation(4.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // آیکون برنامه
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .background(
                        MaterialTheme.colorScheme.primaryContainer,
                        MaterialTheme.shapes.medium
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = appInfo.name.take(1),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }
            
            Spacer(modifier = Modifier.width(16.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = appInfo.name,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = appInfo.packageName,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "ورژن: ${appInfo.versionName} (${appInfo.versionCode})",
                    style = MaterialTheme.typography.bodySmall
                )
            }
            
            // نشانگر ریسک
            securityScan?.let { scan ->
                RiskIndicator(
                    riskLevel = scan.riskLevel,
                    score = scan.score
                )
            }
        }
    }
}

@Composable
private fun AppInfoSection(appInfo: org.apz.core.model.AppInfo) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        elevation = CardDefaults.cardElevation(2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "اطلاعات برنامه",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            
            InfoRow("نوع برنامه", if (appInfo.isSystemApp) "سیستمی" else "کاربری")
            InfoRow("وضعیت", if (appInfo.isEnabled) "فعال" else "غیرفعال")
            InfoRow("تاریخ نصب", formatDate(appInfo.installTime))
            InfoRow("آخرین بروزرسانی", formatDate(appInfo.updateTime))
            InfoRow("اندازه", formatFileSize(appInfo.size))
            InfoRow("داده‌ها", formatFileSize(appInfo.dataSize))
            InfoRow("کش", formatFileSize(appInfo.cacheSize))
        }
    }
}

@Composable
private fun SecurityAnalysisSection(
    securityScan: org.apz.core.model.SecurityScanResult?,
    onShowDetails: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = when (securityScan?.riskLevel) {
                RiskLevel.LOW -> MaterialTheme.colorScheme.surfaceVariant
                RiskLevel.MEDIUM -> MaterialTheme.colorScheme.surface
                RiskLevel.HIGH -> MaterialTheme.colorScheme.errorContainer
                RiskLevel.CRITICAL -> MaterialTheme.colorScheme.errorContainer
                null -> MaterialTheme.colorScheme.surface
            }
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column {
                    Text(
                        text = "تحلیل امنیتی",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    securityScan?.let { scan ->
                        Text(
                            text = "امتیاز ریسک: ${scan.score}/100",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
                
                Button(
                    onClick = onShowDetails,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = when (securityScan?.riskLevel) {
                            RiskLevel.LOW -> MaterialTheme.colorScheme.primary
                            RiskLevel.MEDIUM -> MaterialTheme.colorScheme.onSurface
                            RiskLevel.HIGH -> MaterialTheme.colorScheme.error
                            RiskLevel.CRITICAL -> MaterialTheme.colorScheme.error
                            null -> MaterialTheme.colorScheme.primary
                        }
                    )
                ) {
                    Text("مشاهده جزئیات")
                }
            }
            
            securityScan?.warnings?.take(3)?.forEach { warning ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(vertical = 4.dp)
                ) {
                    Icon(
                        imageVector = when (warning.severity) {
                            RiskLevel.LOW -> Icons.Default.CheckCircle
                            RiskLevel.MEDIUM -> Icons.Default.Warning
                            RiskLevel.HIGH -> Icons.Default.Error
                            RiskLevel.CRITICAL -> Icons.Default.Dangerous
                        },
                        contentDescription = null,
                        tint = when (warning.severity) {
                            RiskLevel.LOW -> MaterialTheme.colorScheme.primary
                            RiskLevel.MEDIUM -> MaterialTheme.colorScheme.onSurface
                            RiskLevel.HIGH -> MaterialTheme.colorScheme.error
                            RiskLevel.CRITICAL -> MaterialTheme.colorScheme.error
                        }
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = warning.title,
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}

@Composable
private fun ActionSection(
    onBackup: () -> Unit,
    onClearCache: () -> Unit,
    onAnalyze: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        OutlinedButton(
            onClick = onBackup,
            modifier = Modifier.weight(1f)
        ) {
            Icon(Icons.Default.Backup, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("بکاپ")
        }
        
        OutlinedButton(
            onClick = onClearCache,
            modifier = Modifier.weight(1f)
        ) {
            Icon(Icons.Default.Cleanup, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("پاکسازی کش")
        }
        
        OutlinedButton(
            onClick = onAnalyze,
            modifier = Modifier.weight(1f)
        ) {
            Icon(Icons.Default.Security, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("تحلیل مجدد")
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

private fun formatDate(timestamp: Long): String {
    return java.text.SimpleDateFormat("yyyy/MM/dd", java.util.Locale.getDefault())
        .format(java.util.Date(timestamp))
}

private fun formatFileSize(bytes: Long): String {
    return when {
        bytes >= 1024 * 1024 * 1024 -> "%.1f GB".format(bytes / (1024.0 * 1024 * 1024))
        bytes >= 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024))
        bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
        else -> "$bytes B"
    }
}