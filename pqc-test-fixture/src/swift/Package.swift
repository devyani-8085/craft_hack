// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "CryptoFixture",
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", exact: "1.4.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "2.0.0"),
    ]
)
