package fr.bonobo.localauth.data

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import fr.bonobo.localauth.security.CryptoManager

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        val crypto = CryptoManager()
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS `accounts_new` (
                `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                `issuerCiphertext` TEXT NOT NULL,
                `issuerIv` TEXT NOT NULL,
                `labelCiphertext` TEXT NOT NULL,
                `labelIv` TEXT NOT NULL,
                `secretCiphertext` TEXT NOT NULL,
                `secretIv` TEXT NOT NULL,
                `digits` INTEGER NOT NULL,
                `period` INTEGER NOT NULL,
                `algorithm` TEXT NOT NULL,
                `createdAt` INTEGER NOT NULL
            )
        """.trimIndent())
        val cursor = db.query("SELECT id, issuer, label, secretCiphertext, secretIv, digits, period, algorithm, createdAt FROM accounts")
        try {
            while (cursor.moveToNext()) {
                val issuer = crypto.encrypt(cursor.getString(1).encodeToByteArray())
                val label = crypto.encrypt(cursor.getString(2).encodeToByteArray())
                db.execSQL(
                    """INSERT INTO accounts_new
                    (id, issuerCiphertext, issuerIv, labelCiphertext, labelIv, secretCiphertext, secretIv, digits, period, algorithm, createdAt)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""".trimIndent(),
                    arrayOf(cursor.getLong(0), issuer.ciphertext, issuer.iv, label.ciphertext, label.iv,
                        cursor.getString(3), cursor.getString(4), cursor.getInt(5), cursor.getInt(6),
                        cursor.getString(7), cursor.getLong(8))
                )
            }
        } finally { cursor.close() }
        db.execSQL("DROP TABLE accounts")
        db.execSQL("ALTER TABLE accounts_new RENAME TO accounts")
    }
}
