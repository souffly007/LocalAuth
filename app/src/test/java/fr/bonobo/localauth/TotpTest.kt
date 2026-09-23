package fr.bonobo.localauth
import fr.bonobo.localauth.security.Totp
import org.junit.Assert.assertEquals
import org.junit.Test
class TotpTest { @Test fun rfc6238Vector() { assertEquals("94287082", Totp.code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59_000, 30, 8, "SHA1")) } }
