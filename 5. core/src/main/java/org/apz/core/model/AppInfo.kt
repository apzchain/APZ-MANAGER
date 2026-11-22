package org.apz.core.model

import android.graphics.drawable.Drawable

data class AppInfo(
    val packageName: String,
    val name: String,
    val version: String,
    val icon: Drawable?,
    val installTime: Long = 0,
    val updateTime: Long = 0,
    val targetSdk: Int = 0,
    val permissions: List<String> = emptyList()
)