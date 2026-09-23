package fr.bonobo.localauth

import android.app.Application
import androidx.room.Room
import fr.bonobo.localauth.data.AppDatabase
import fr.bonobo.localauth.data.MIGRATION_1_2

class LocalAuthApp : Application() {
    val db by lazy { Room.databaseBuilder(this, AppDatabase::class.java, "localauth.db").addMigrations(MIGRATION_1_2).build() }
}
