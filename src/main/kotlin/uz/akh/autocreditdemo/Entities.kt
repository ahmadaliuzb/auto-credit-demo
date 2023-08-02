package uz.akh.autocreditdemo

import com.fasterxml.jackson.annotation.JsonIgnore
import org.hibernate.annotations.ColumnDefault
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import org.springframework.data.jpa.repository.Temporal
import java.math.BigDecimal
import java.util.*
import javax.persistence.*


/**
02/08/2023 - 4:53 PM
Created by Akhmadali


 */

@MappedSuperclass
@EntityListeners(AuditingEntityListener::class)
class BaseEntity(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) var id: Long? = null,
    @CreatedDate @Temporal(TemporalType.TIMESTAMP) var createdDate: Date? = null,
    @LastModifiedDate @Temporal(TemporalType.TIMESTAMP) var modifiedDate: Date? = null,
    @Column(nullable = false) @ColumnDefault(value = "false") var deleted: Boolean = false
)

@Entity(name = "users")
class User(

    @Column(length = 128) var fullName: String,

    @Column var username: String,

    @Column(length = 64)
    @JsonIgnore
    var password: String,

    @Column
    var phone: String,


    @Enumerated(EnumType.STRING)
    var role: Role,
) : BaseEntity()


@Entity(name = "clients")
class Client(
    @Column(length = 128) var fullName: String,

    @Column(length = 128) val externalId: String,

    @Column() val pinfl: String,

    @Column val tin: String,

    @Column val type: String,

    @Column var available: Boolean,

    ) : BaseEntity()

@Entity(name = "models")
class Model(
    val name: String,
    val externalId: String
) : BaseEntity()


@Entity(name = "files")
class File(
    val name: String,

    val extension: String,

    val size: Long,

    val contentType: String,

    val hashId: String,

    val uploadFolder: String,

    val uploadFileName: String,

    var active: Boolean

) : BaseEntity()


@Entity(name = "modifications")
class Modification(
    @Column(length = 64) var name: String,

    @ManyToOne val model: Model,

    @Column(length = 64) var colorName: String,

    @Column(length = 64) var hexValue: String,

    @OneToOne var image: File,

    @Column(length = 16) var fuelConsumption: String,

    @Column(length = 64) var horsePower: String,

    @Column(length = 32) var transmissions: String,

    @Column(length = 16) var accleration: String


) : BaseEntity()

@Entity(name = "contracts")
class Contract(

    @Column(length = 128) val contractCode: String,

    var orderId: Long,

    @ManyToOne val client: Client,

    val dealerId: Long,

    @Column(length = 128) val dealerName: String,

    var orderKind: String,

    @Enumerated(EnumType.STRING)
    var status: Status,

    @Temporal(TemporalType.TIMESTAMP) var orderDate: Date,

    var price: BigDecimal,

    var paidAmount: BigDecimal,

    val vinCode: String,

    @Temporal(TemporalType.TIMESTAMP) var cancelledDate: Date,

    var cancelledNote: String,

    var queueNumber: Long,

    var contractApproved: String,

    var readyOrderInSup: String,

    var prePaymentAmount: BigDecimal,

    var remainAmount: BigDecimal,

    @Temporal(TemporalType.TIMESTAMP) var expectDate: Date,

    @Temporal(TemporalType.TIMESTAMP) var producedDate: Date,

    @ManyToOne var modification: Modification,

    @OneToOne val contractFile: File

) : BaseEntity()


@Entity(name = "queue_histories")
class QueueHistory(
    @OneToOne val contract: Contract,

    var previousQueue: Long,

    var currentQueue: Long,

    var difference: Long,

    @Temporal(TemporalType.TIMESTAMP) var date: Date,

    ) : BaseEntity()