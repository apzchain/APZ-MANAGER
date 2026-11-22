package org.apz.manager.ui

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import org.apz.manager.feature.details.AppDetailsViewModel

sealed class Screen(val route: String) {
    object Home : Screen("home")
    object Install : Screen("install")
    object Details : Screen("details/{packageName}") {
        fun createRoute(packageName: String) = "details/$packageName"
    }
    object Cleanup : Screen("cleanup")
}

@Composable
fun ApzApp() {
    val navController = rememberNavController()
    
    NavHost(
        navController = navController,
        startDestination = Screen.Home.route
    ) {
        composable(Screen.Home.route) {
            HomeScreen(
                onAppClick = { packageName ->
                    navController.navigate(Screen.Details.createRoute(packageName))
                },
                onInstallClick = { navController.navigate(Screen.Install.route) },
                onCleanupClick = { navController.navigate(Screen.Cleanup.route) }
            )
        }
        
        composable(Screen.Install.route) {
            InstallScreen(onBack = { navController.popBackStack() })
        }
        
        composable(Screen.Details.route) { backStackEntry ->
            val packageName = backStackEntry.arguments?.getString("packageName") ?: ""
            AppDetailsScreen(
                packageName = packageName,
                onBack = { navController.popBackStack() }
            )
        }
        
        composable(Screen.Cleanup.route) {
            CleanupScreen(onBack = { navController.popBackStack() })
        }
    }
}