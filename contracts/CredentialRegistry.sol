// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title CredentialRegistry
/// @notice Registry minimal untuk status kredensial pendidikan.
/// @dev Hanya menyimpan hash kredensial + status. Tidak ada data pribadi on-chain.
///      Prototype akademik: tidak diaudit, jangan dipakai di mainnet.
contract CredentialRegistry {
    // ---------- Types ----------
    enum Status { None, Issued, Revoked }

    struct Record {
        address issuer;
        uint64 issuedAt;
        uint64 revokedAt;
        uint8 reasonCode; // 0 = n/a, 1 = kesalahan input, 2 = pencabutan akademik, 3 = lainnya
        Status status;
    }

    // ---------- State ----------
    address public admin;
    address public pendingAdmin;
    bool public paused;

    mapping(address => bool) public isIssuer;
    mapping(bytes32 => Record) private records;

    // ---------- Events ----------
    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    event CredentialIssued(bytes32 indexed credHash, address indexed issuer, uint64 issuedAt);
    event CredentialRevoked(bytes32 indexed credHash, address indexed by, uint8 reasonCode, uint64 revokedAt);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event AdminTransferStarted(address indexed current, address indexed proposed);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    // ---------- Errors ----------
    error NotAdmin();
    error NotIssuer();
    error NotAuthorizedToRevoke();
    error ContractPaused();
    error ZeroHash();
    error ZeroAddress();
    error AlreadyExists();
    error NotFound();
    error AlreadyRevoked();
    error InvalidReason();
    error NotPendingAdmin();

    // ---------- Modifiers ----------
    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    constructor() {
        admin = msg.sender;
        emit AdminTransferred(address(0), msg.sender);
    }

    // ---------- Governance ----------
    function addIssuer(address issuer) external onlyAdmin {
        if (issuer == address(0)) revert ZeroAddress();
        isIssuer[issuer] = true;
        emit IssuerAdded(issuer);
    }

    function removeIssuer(address issuer) external onlyAdmin {
        isIssuer[issuer] = false;
        emit IssuerRemoved(issuer);
    }

    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Pergantian admin dua langkah untuk mencegah salah alamat.
    function proposeAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        emit AdminTransferred(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }

    // ---------- Core ----------
    function issue(bytes32 credHash) external whenNotPaused {
        if (!isIssuer[msg.sender]) revert NotIssuer();
        if (credHash == bytes32(0)) revert ZeroHash();
        if (records[credHash].status != Status.None) revert AlreadyExists();

        uint64 ts = uint64(block.timestamp);
        records[credHash] = Record({
            issuer: msg.sender,
            issuedAt: ts,
            revokedAt: 0,
            reasonCode: 0,
            status: Status.Issued
        });
        emit CredentialIssued(credHash, msg.sender, ts);
    }

    /// @notice Pencabutan oleh penerbit asli, atau admin (jalur sengketa).
    function revoke(bytes32 credHash, uint8 reasonCode) external whenNotPaused {
        Record storage r = records[credHash];
        if (r.status == Status.None) revert NotFound();
        if (r.status == Status.Revoked) revert AlreadyRevoked();
        if (reasonCode == 0 || reasonCode > 3) revert InvalidReason();

        bool originalIssuer = (msg.sender == r.issuer && isIssuer[msg.sender]);
        if (!originalIssuer && msg.sender != admin) revert NotAuthorizedToRevoke();

        r.status = Status.Revoked;
        r.revokedAt = uint64(block.timestamp);
        r.reasonCode = reasonCode;
        emit CredentialRevoked(credHash, msg.sender, reasonCode, r.revokedAt);
    }

    /// @notice Verifikasi publik (read-only, tanpa biaya gas).
    /// @return status status kredensial
    /// @return issuer alamat penerbit
    /// @return issuerActive apakah penerbit masih terdaftar aktif saat ini
    /// @return issuedAt waktu penerbitan
    /// @return revokedAt waktu pencabutan (0 bila belum)
    function verify(bytes32 credHash)
        external
        view
        returns (Status status, address issuer, bool issuerActive, uint64 issuedAt, uint64 revokedAt)
    {
        Record storage r = records[credHash];
        return (r.status, r.issuer, isIssuer[r.issuer], r.issuedAt, r.revokedAt);
    }
}
