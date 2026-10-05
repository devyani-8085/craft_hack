name := "crypto-fixture"
scalaVersion := "2.13.12"
libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.60",
  "com.pauldijou" %% "jwt-core" % "4.0.0"
)
