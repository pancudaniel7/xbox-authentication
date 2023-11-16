import java.io.FileInputStream
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.*
import javax.net.ssl.*

fun loadCertificateFromKeystore(keystorePath: String, keystorePassword: String): SSLContext {
    val keyStore = KeyStore.getInstance("PKCS12").apply {
        load(FileInputStream(keystorePath), keystorePassword.toCharArray())
    }

    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
        init(keyStore, keystorePassword.toCharArray())
    }

    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
        init(keyStore)
    }

    return SSLContext.getInstance("TLS").apply {
        init(keyManagerFactory.keyManagers, trustManagerFactory.trustManagers, null)
    }
}

fun createDataToSign(
    httpMethod: String,
    fullUrl: String,
    headers: Map<String, String>,
    body: ByteArray,
    policyVersion: Int
): ByteArray {
    val buffer = ByteBuffer.allocate(1024) // Adjust the size as needed
    buffer.order(ByteOrder.BIG_ENDIAN)

    // Add Policy Version
    buffer.putInt(policyVersion)
    buffer.put(0x00) // null byte separator

    // Add Timestamp
    val timestamp = Instant.now().toEpochMilli()
    buffer.putLong(timestamp)
    buffer.put(0x00) // null byte separator

    // Add HTTP Method
    buffer.put(httpMethod.toByteArray(Charsets.US_ASCII))
    buffer.put(0x00) // null byte separator

    // Add Path and Query String
    val url = URL(fullUrl)
    val path = url.path + if (url.query != null) "?${url.query}" else ""
    buffer.put(path.toByteArray(Charsets.US_ASCII))
    buffer.put(0x00) // null byte separator

    // Add Headers (e.g., Authorization, Content-Type, etc.)
    headers.forEach { (key, value) ->
        buffer.put(value.toByteArray(Charsets.US_ASCII))
        buffer.put(0x00) // null byte separator
    }

    // Add Body
    val maxBodyBytes = 8192 // or the maximum size specified by the signature policy
    if (body.isNotEmpty()) {
        buffer.put(body.copyOfRange(0, kotlin.math.min(body.size, maxBodyBytes)))
    }
    buffer.put(0x00) // null byte separator

    return buffer.array().sliceArray(0 until buffer.position())
}

fun encodeCoordinateToBase64URL(coordinate: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(coordinate)
}

fun generatePostData(ecPublicKey: ECPublicKey): String {
    val x = encodeCoordinateToBase64URL(ecPublicKey.w.affineX.toByteArray())
    val y = encodeCoordinateToBase64URL(ecPublicKey.w.affineY.toByteArray())

    return """
        {
            "Properties": {
                "ProofKey": {
                    "alg": "ES256",
                    "kty": "EC",
                    "use": "sig",
                    "crv": "P-256",
                    "x": "$x",
                    "y": "$y"
                }
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }
    """.trimIndent()
}

fun createSignature(privateKey: PrivateKey, dataToSign: ByteArray): String {
    val signature = Signature.getInstance("SHA256withECDSA")
    signature.initSign(privateKey)
    signature.update(dataToSign)
    return Base64.getEncoder().encodeToString(signature.sign())
}

fun loadKeystore(keystorePath: String, keystorePassword: String): KeyStore {
    val keyStore = KeyStore.getInstance("PKCS12")
    FileInputStream(keystorePath).use { keyStoreFile ->
        keyStore.load(keyStoreFile, keystorePassword.toCharArray())
    }
    return keyStore
}

fun extractPrivateKey(keyStore: KeyStore, alias: String, keyPassword: String): PrivateKey {
    return keyStore.getKey(alias, keyPassword.toCharArray()) as PrivateKey
}

fun extractPublicKey(keyStore: KeyStore, alias: String): PublicKey {
    val cert: java.security.cert.Certificate = keyStore.getCertificate(alias)
    return cert.publicKey
}

fun makeAuthenticatedPostRequest(
    url: String,
    sslContext: SSLContext,
    headers: Map<String, String>,
    postData: String
) {
    try {
        val connection = (URL(url).openConnection() as HttpsURLConnection).apply {
            sslSocketFactory = sslContext.socketFactory
            requestMethod = "POST"
            doOutput = true

            headers.forEach { (key, value) -> setRequestProperty(key, value) }
        }

        connection.outputStream.use { outputStream ->
            outputStream.write(postData.toByteArray())
            outputStream.flush()
        }

        val response = connection.inputStream.bufferedReader().use { it.readText() }
        println(response)
    } catch (e: Exception) {
        e.printStackTrace()
    }
}

fun main(args: Array<String>) {

    val sslKeystorePath = "/Users/pancudaniel/test.pfx"
    val ecKeystorePath = "/Users/pancudaniel/ec-keystore.jks"

    val pfxPassword = "wVw3jyMEJAdKUrBdRWAP"
    val universalKeystorePassword = "aremere"

    val sslKeysAlias = "te-a5fa38aa-88bc-4f45-817a-9729338b21ac"
    val ecKeysAlias = "ec-key-pair"
    val url = "https://service.auth.xboxlive.com/service/authenticate"

    val authenticationHeaders = mapOf(
        "x-xbl-contract-version" to "1",
        "Content-Type" to "application/json",
    )

    val sslContext: SSLContext = loadCertificateFromKeystore(sslKeystorePath, pfxPassword)

    // extract EC keys
    val ecKeystore: KeyStore = loadKeystore(ecKeystorePath, universalKeystorePassword)

    val ecPrivateKey: PrivateKey = extractPrivateKey(ecKeystore, ecKeysAlias, universalKeystorePassword)
    val ecPublicKey: PublicKey = extractPublicKey(ecKeystore, ecKeysAlias)

    // generate post data
    val postData = generatePostData(ecPublicKey as ECPublicKey)
    val postDataByteArray = postData.toByteArray(Charsets.UTF_8)
    val dataToSign = createDataToSign("POST", url, authenticationHeaders, postDataByteArray, 1)

    // create the signature
    val signature = createSignature(ecPrivateKey, dataToSign)
    val headersWithSignature = authenticationHeaders.toMutableMap()
    headersWithSignature["Signature"] = signature;

    // trigger authenticate request
    makeAuthenticatedPostRequest(url, sslContext, headersWithSignature, postData)
}

