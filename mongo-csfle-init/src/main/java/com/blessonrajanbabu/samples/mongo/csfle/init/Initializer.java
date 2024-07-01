package com.blessonrajanbabu.samples.mongo.csfle.init;

import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.model.vault.RewrapManyDataKeyOptions;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.BsonDocument;
import org.bson.Document;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;

public class Initializer {

    private static final String VAULT_DATABASE = "encryption";
    private static final String KEY_VAULT = "__keyVault";
    private static final String SECONDARY_KEY_VAULT = "__keyVaultSecondary";
    private static final String LOCAL_KEY_VAULT = "__keyVaultLocal";
    private static final List<String> KEY_IDS = List.of("default-key", "pci-key");

    public static void main(String[] args) {

        String url = getEnv("MONGODB_URL");
        String primaryKmsArn = getEnv("PRIMARY_KMS_ARN");
        String primaryKmsRegion = getEnv("PRIMARY_KMS_REGION");
        String secondaryKmsArn = getEnv("SECONDARY_KMS_ARN");
        String secondaryKmsRegion = getEnv("SECONDARY_KMS_REGION");

        var clientSettings = MongoClientSettings.builder()
                .applyConnectionString(new ConnectionString(url))
                .build();

        try (var client = MongoClients.create(clientSettings)) {
            var database = client.getDatabase(VAULT_DATABASE);
            assertVaultNotInitialized(database);
            createVaults(database);
            createDataKeys(primaryKmsArn, primaryKmsRegion, clientSettings);
            copyDataKeys(database);
        }

        GenerateDataKeyResponse localMasterKeyResponse = createLocalMasterKey(primaryKmsArn, primaryKmsRegion);
        byte[] localMasterKey = localMasterKeyResponse.plaintext().asByteArray();
        System.out.printf("Encrypted local master key = \"%s\". Add it to your secrets manager.%n", Base64.getEncoder().encodeToString(localMasterKeyResponse.ciphertextBlob().asByteArray()));

        reWrapAltDataKeys(secondaryKmsArn, secondaryKmsRegion, clientSettings);
        reWrapLocalDataKeys(localMasterKey, clientSettings);
    }

    private static String getEnv(String key) {
        var value = System.getenv(key);
        if (value == null) {
            System.out.println(key + " missing");
            System.exit(1);
        }
        return value;
    }

    private static void assertVaultNotInitialized(MongoDatabase database) {
        StreamSupport.stream(database.listCollectionNames().spliterator(), false)
                .findAny()
                .ifPresent(x -> {
                    System.out.println("Key vault already exists. Delete it before re-initializing.");
                    System.exit(1);
                });
    }

    private static void createVaults(MongoDatabase database) {
        createVault(KEY_VAULT, database);
        createVault(SECONDARY_KEY_VAULT, database);
        createVault(LOCAL_KEY_VAULT, database);
    }

    private static void createVault(String vault, MongoDatabase database) {
        var collection = database.getCollection(vault);
        var keys = new Document(Map.of("keyAltNames", 1));
        var options = new IndexOptions()
                .partialFilterExpression(new Document(Map.of("keyAltNames", Map.of("$exists", true))))
                .unique(true);
        collection.createIndex(keys, options);
    }

    private static void createDataKeys(String primaryKmsArn, String primaryKmsRegion, MongoClientSettings clientSettings) {
        KEY_IDS.forEach(x -> createDataKey(x, KEY_VAULT, primaryKmsArn, primaryKmsRegion, clientSettings));
    }

    private static void createDataKey(String keyId, String vault, String kmsArn, String kmsRegion, MongoClientSettings clientSettings) {
        var masterKey = BsonDocument.parse("""
                {
                    "provider": "aws",
                    "key": "%s",
                    "region": "%s"
                }
                """.formatted(kmsArn, kmsRegion));
        var encryptionSettings = ClientEncryptionSettings.builder()
                .keyVaultNamespace(VAULT_DATABASE + "." + vault)
                .keyVaultMongoClientSettings(clientSettings)
                .kmsProviders(Map.of("aws", Map.of()))
                .build();
        try (var clientEncryption = ClientEncryptions.create(encryptionSettings)) {
            clientEncryption.createDataKey("aws", new DataKeyOptions().keyAltNames(List.of(keyId)).masterKey(masterKey));
        }
    }

    private static void copyDataKeys(MongoDatabase database) {
        copyDataKeys(SECONDARY_KEY_VAULT, database);
        copyDataKeys(LOCAL_KEY_VAULT, database);
    }

    private static void copyDataKeys(String target, MongoDatabase database) {
        var vault = database.getCollection(target);
        database.getCollection(KEY_VAULT).find().forEach(vault::insertOne);
    }

    private static GenerateDataKeyResponse createLocalMasterKey(String kmsArn, String kmsRegion) {
        var dataKeyRequest = GenerateDataKeyRequest.builder().keyId(kmsArn).numberOfBytes(96).build();
        try (var kmsClient = KmsClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(Region.of(kmsRegion))
                .build()) {
            return kmsClient.generateDataKey(dataKeyRequest);
        }
    }

    private static void reWrapAltDataKeys(String kmsArn, String kmsRegion, MongoClientSettings clientSettings) {
        var masterKey = BsonDocument.parse("""
                {
                    "provider": "aws",
                    "key": "%s",
                    "region": "%s"
                }
                """.formatted(kmsArn, kmsRegion));
        var encryptionSettings = ClientEncryptionSettings.builder()
                .keyVaultNamespace("%s.%s".formatted(VAULT_DATABASE, SECONDARY_KEY_VAULT))
                .keyVaultMongoClientSettings(clientSettings)
                .kmsProviders(Map.of("aws", Map.of()))
                .build();
        RewrapManyDataKeyOptions reWrapOptions = new RewrapManyDataKeyOptions().provider("aws").masterKey(masterKey);
        try (var clientEncryption = ClientEncryptions.create(encryptionSettings)) {
            clientEncryption.rewrapManyDataKey(Filters.exists("_id"), reWrapOptions);
        }
    }

    private static void reWrapLocalDataKeys(byte[] masterKey, MongoClientSettings clientSettings) {
        var encryptionSettings = ClientEncryptionSettings.builder()
                .keyVaultNamespace("%s.%s".formatted(VAULT_DATABASE, LOCAL_KEY_VAULT))
                .keyVaultMongoClientSettings(clientSettings)
                .kmsProviders(Map.of("aws", Map.of(), "local", Map.of("key", masterKey)))
                .build();
        RewrapManyDataKeyOptions reWrapOptions = new RewrapManyDataKeyOptions().provider("local");
        try (var clientEncryption = ClientEncryptions.create(encryptionSettings)) {
            clientEncryption.rewrapManyDataKey(Filters.exists("_id"), reWrapOptions);
        }
    }

}
