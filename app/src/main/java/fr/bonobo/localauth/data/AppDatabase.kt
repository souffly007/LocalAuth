package fr.bonobo.localauth.data

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "accounts")
data class AccountEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val issuerCiphertext: String,
    val issuerIv: String,
    val labelCiphertext: String,
    val labelIv: String,
    val secretCiphertext: String,
    val secretIv: String,
    val digits: Int = 6,
    val period: Int = 30,
    val algorithm: String = "SHA1",
    val createdAt: Long = System.currentTimeMillis()
)

data class Account(
    val id: Long,
    val issuer: String,
    val label: String,
    internal val secretCiphertext: String,
    internal val secretIv: String,
    val digits: Int,
    val period: Int,
    val algorithm: String,
    val createdAt: Long
)

@Dao interface AccountDao {
    @Query("SELECT * FROM accounts") fun observeAll(): Flow<List<AccountEntity>>
    @Query("SELECT * FROM accounts") suspend fun getAll(): List<AccountEntity>
    @Insert suspend fun insert(account: AccountEntity)
    @Query("DELETE FROM accounts WHERE id = :id") suspend fun deleteById(id: Long)
}

@Database(entities = [AccountEntity::class], version = 2, exportSchema = true)
abstract class AppDatabase : RoomDatabase() { abstract fun accounts(): AccountDao }
