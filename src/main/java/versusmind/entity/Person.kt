package versusmind.entity

import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id


@Entity
class Person {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO) var id: Int = 0


    var username: String = ""
    var password: String = ""

    constructor(username: String, password: String) {
        this.username = username
        this.password = password
    }
    constructor() {
    }
}
/*
@Entity
class Person : User() {
    @Id @GeneratedValue(strategy = GenerationType.AUTO) var id: Int = 0


  //   constructor(person: Person) : this(0, person.username, person.password)
  //  constructor(username: String, password: String) : this(@Id @GeneratedValue(strategy = GenerationType.AUTO), username, password)


    override fun toString(): String {
        return  "{ username: \"$username\", password: \"$password\" }"
    }

 }*/