package com.hibouhq.hibou.ide

import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.jetbrains.jsonSchema.extension.JsonSchemaFileProvider
import com.jetbrains.jsonSchema.extension.JsonSchemaProviderFactory
import com.jetbrains.jsonSchema.extension.SchemaType
import com.jetbrains.jsonSchema.remote.JsonFileResolver

// Loaded only when the JSON module is present (hibou-json.xml).

/** Validates .hibou.yaml against the configured server's schema. */
class HibouSchemaProviderFactory : JsonSchemaProviderFactory, DumbAware {
    override fun getProviders(project: Project): List<JsonSchemaFileProvider> = listOf(object : JsonSchemaFileProvider {
        override fun isAvailable(file: VirtualFile) = file.name == ".hibou.yaml" || file.name == ".hibou.yml"
        override fun getName() = "hibou configuration"
        override fun getSchemaFile(): VirtualFile? =
            ServerUrl.resolve()?.let { JsonFileResolver.urlToFile("$it/api/v1/schemas/hibou-config.schema.json") }
        override fun getSchemaType() = SchemaType.remoteSchema
        override fun getRemoteSource(): String? = ServerUrl.resolve()?.let { "$it/api/v1/schemas/hibou-config.schema.json" }
    })
}
