description = "clusterator..."

zapAddOn {
    addOnName.set("clusterator")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
