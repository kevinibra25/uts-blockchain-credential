const { expect } = require("chai");
const { ethers } = require("hardhat");

// Semua data dummy. Hash dibuat dari string contoh, bukan data pribadi.
const H1 = ethers.id("DUMMY-CRED-001");
const H2 = ethers.id("DUMMY-CRED-002");

describe("CredentialRegistry", function () {
  let reg, admin, issuer, other, verifier;

  beforeEach(async () => {
    [admin, issuer, other, verifier] = await ethers.getSigners();
    reg = await (await ethers.getContractFactory("CredentialRegistry")).deploy();
    await reg.waitForDeployment();
  });

  // T-01 (REQ-01: admin dapat menambah penerbit)
  it("T-01 admin menambah issuer -> event IssuerAdded", async () => {
    await expect(reg.addIssuer(issuer.address))
      .to.emit(reg, "IssuerAdded").withArgs(issuer.address);
    expect(await reg.isIssuer(issuer.address)).to.equal(true);
  });

  // T-02 (REQ-02: issuer sah dapat menerbitkan) - happy path
  it("T-02 issuer sah menerbitkan kredensial -> status Issued", async () => {
    await reg.addIssuer(issuer.address);
    await expect(reg.connect(issuer).issue(H1)).to.emit(reg, "CredentialIssued");
    const v = await reg.connect(verifier).verify(H1);
    expect(v.status).to.equal(1n); // Issued
    expect(v.issuer).to.equal(issuer.address);
    expect(v.issuerActive).to.equal(true);
  });

  // T-03 (REQ-03: hanya issuer terdaftar) - unauthorized
  it("T-03 non-issuer menerbitkan -> revert NotIssuer", async () => {
    await expect(reg.connect(other).issue(H1))
      .to.be.revertedWithCustomError(reg, "NotIssuer");
  });

  // T-04 (REQ-04: hash unik) - negative
  it("T-04 menerbitkan hash duplikat -> revert AlreadyExists", async () => {
    await reg.addIssuer(issuer.address);
    await reg.connect(issuer).issue(H1);
    await expect(reg.connect(issuer).issue(H1))
      .to.be.revertedWithCustomError(reg, "AlreadyExists");
  });

  // T-05 (REQ-04: input valid) - negative
  it("T-05 menerbitkan zero hash -> revert ZeroHash", async () => {
    await reg.addIssuer(issuer.address);
    await expect(reg.connect(issuer).issue(ethers.ZeroHash))
      .to.be.revertedWithCustomError(reg, "ZeroHash");
  });

  // T-06 (REQ-05: pencabutan oleh penerbit asli) - happy path
  it("T-06 issuer asli mencabut -> status Revoked + event", async () => {
    await reg.addIssuer(issuer.address);
    await reg.connect(issuer).issue(H1);
    await expect(reg.connect(issuer).revoke(H1, 1))
      .to.emit(reg, "CredentialRevoked");
    const v = await reg.verify(H1);
    expect(v.status).to.equal(2n); // Revoked
    expect(v.revokedAt).to.be.gt(0n);
  });

  // T-07 (REQ-05: otorisasi pencabutan) - unauthorized
  it("T-07 pihak lain mencabut -> revert NotAuthorizedToRevoke", async () => {
    await reg.addIssuer(issuer.address);
    await reg.connect(issuer).issue(H1);
    await expect(reg.connect(other).revoke(H1, 1))
      .to.be.revertedWithCustomError(reg, "NotAuthorizedToRevoke");
  });

  // T-08 (REQ-05: jalur sengketa oleh admin)
  it("T-08 admin dapat mencabut (jalur sengketa)", async () => {
    await reg.addIssuer(issuer.address);
    await reg.connect(issuer).issue(H1);
    await reg.revoke(H1, 2);
    expect((await reg.verify(H1)).status).to.equal(2n);
  });

  // T-09 (REQ-06: pencabutan tidak ganda / tidak ada) - negative
  it("T-09 cabut dua kali / cabut hash tak ada -> revert", async () => {
    await reg.addIssuer(issuer.address);
    await reg.connect(issuer).issue(H1);
    await reg.connect(issuer).revoke(H1, 1);
    await expect(reg.connect(issuer).revoke(H1, 1))
      .to.be.revertedWithCustomError(reg, "AlreadyRevoked");
    await expect(reg.connect(issuer).revoke(H2, 1))
      .to.be.revertedWithCustomError(reg, "NotFound");
  });

  // T-10 (REQ-06: reason code valid) - negative
  it("T-10 reason code tidak valid -> revert InvalidReason", async () => {
    await reg.addIssuer(issuer.address);
    await reg.connect(issuer).issue(H1);
    await expect(reg.connect(issuer).revoke(H1, 0))
      .to.be.revertedWithCustomError(reg, "InvalidReason");
    await expect(reg.connect(issuer).revoke(H1, 9))
      .to.be.revertedWithCustomError(reg, "InvalidReason");
  });

  // T-11 (REQ-07: verifikasi publik tanpa hak akses)
  it("T-11 hash tak dikenal -> verify mengembalikan None", async () => {
    const v = await reg.connect(verifier).verify(H2);
    expect(v.status).to.equal(0n);
  });

  // T-12 (REQ-08: emergency pause) - recovery
  it("T-12 pause memblokir issue/revoke; unpause memulihkan", async () => {
    await reg.addIssuer(issuer.address);
    await reg.pause();
    await expect(reg.connect(issuer).issue(H1))
      .to.be.revertedWithCustomError(reg, "ContractPaused");
    await reg.unpause();
    await expect(reg.connect(issuer).issue(H1)).to.emit(reg, "CredentialIssued");
  });

  // T-13 (REQ-09: key issuer dikompromikan -> cabut hak issuer) - recovery
  it("T-13 issuer dihapus -> tidak bisa issue/revoke, verify menandai issuerActive=false", async () => {
    await reg.addIssuer(issuer.address);
    await reg.connect(issuer).issue(H1);
    await reg.removeIssuer(issuer.address);
    await expect(reg.connect(issuer).issue(H2))
      .to.be.revertedWithCustomError(reg, "NotIssuer");
    await expect(reg.connect(issuer).revoke(H1, 1))
      .to.be.revertedWithCustomError(reg, "NotAuthorizedToRevoke");
    const v = await reg.verify(H1);
    expect(v.issuerActive).to.equal(false);
    // admin tetap bisa mencabut kredensial yang dikeluarkan key terkompromi
    await reg.revoke(H1, 3);
    expect((await reg.verify(H1)).status).to.equal(2n);
  });

  // T-14 (REQ-10: tata kelola admin dua langkah)
  it("T-14 admin transfer dua langkah; non-admin ditolak", async () => {
    await expect(reg.connect(other).addIssuer(other.address))
      .to.be.revertedWithCustomError(reg, "NotAdmin");
    await reg.proposeAdmin(other.address);
    await expect(reg.connect(verifier).acceptAdmin())
      .to.be.revertedWithCustomError(reg, "NotPendingAdmin");
    await reg.connect(other).acceptAdmin();
    expect(await reg.admin()).to.equal(other.address);
  });
});
