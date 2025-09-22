(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PROOF (err u101))
(define-constant ERR-ALREADY-VERIFIED (err u102))
(define-constant ERR-NOT-VERIFIED (err u103))
(define-constant ERR-EXPIRED (err u104))
(define-constant ERR-REVOKED (err u105))
(define-constant ERR-INVALID-EXPIRY (err u106))
(define-constant ERR-INVALID-LEVEL (err u107))
(define-constant ERR-INSUFFICIENT-LEVEL (err u108))
(define-constant ERR-AUDIT-OVERFLOW (err u109))

(define-constant EVENT-REGISTRATION u1)
(define-constant EVENT-REVOCATION u2)
(define-constant EVENT-UPDATE u3)
(define-constant EVENT-LEVEL-CHECK u4)

(define-constant LEVEL-BASIC u1)
(define-constant LEVEL-STANDARD u2) 
(define-constant LEVEL-PREMIUM u3)

(define-data-var contract-owner principal tx-sender)
(define-data-var oracle-address principal tx-sender)
(define-data-var proof-threshold uint u5)
(define-data-var audit-counter uint u0)

(define-map verified-users 
    principal 
    {proof: (buff 64), 
     timestamp: uint,
     expiry: uint,
     status: bool,
     level: uint})

(define-map oracle-proofs 
    (buff 64) 
    {verified: bool, 
     revoked: bool})

(define-map access-controls
    principal 
    {can-verify: bool,
     can-revoke: bool})

(define-map audit-logs
    uint
    {user: principal,
     event-type: uint,
     timestamp: uint,
     operator: principal,
     level: uint,
     details: (string-ascii 256)})

(define-map user-audit-count
    principal
    uint)

(define-private (log-audit-event (user principal) (event-type uint) (level uint) (details (string-ascii 256)))
    (let ((current-time (get-stacks-block-info? time (- stacks-block-height u1)))
          (audit-id (var-get audit-counter))
          (current-user-count (default-to u0 (map-get? user-audit-count user))))
        (var-set audit-counter (+ audit-id u1))
        (map-set user-audit-count user (+ current-user-count u1))
        (map-set audit-logs audit-id
            {user: user,
             event-type: event-type,
             timestamp: (default-to u0 current-time),
             operator: tx-sender,
             level: level,
             details: details})
        (ok audit-id)))

(define-public (set-oracle-address (new-oracle principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (var-set oracle-address new-oracle))))

(define-public (update-proof-threshold (new-threshold uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (var-set proof-threshold new-threshold))))

(define-public (grant-access-control (operator principal) (can-verify bool) (can-revoke bool))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set access-controls operator {can-verify: can-verify, can-revoke: can-revoke}))))

(define-public (register-proof (user principal) (proof (buff 64)) (expiry uint) (verification-level uint))
    (let ((current-time (get-stacks-block-info? time (- stacks-block-height u1))))
        (asserts! (is-some (map-get? access-controls tx-sender)) ERR-NOT-AUTHORIZED)
        (asserts! (get can-verify (default-to {can-verify: false, can-revoke: false} 
            (map-get? access-controls tx-sender))) ERR-NOT-AUTHORIZED)
        (asserts! (> expiry (default-to u0 current-time)) ERR-INVALID-EXPIRY)
        (asserts! (is-none (map-get? verified-users user)) ERR-ALREADY-VERIFIED)
        (asserts! (or (is-eq verification-level LEVEL-BASIC) 
                      (or (is-eq verification-level LEVEL-STANDARD) 
                          (is-eq verification-level LEVEL-PREMIUM))) ERR-INVALID-LEVEL)
        (map-set oracle-proofs proof {verified: true, revoked: false})
        (map-set verified-users user 
            {proof: proof,
             timestamp: (default-to u0 current-time),
             expiry: expiry,
             status: true,
             level: verification-level})
        (unwrap-panic (log-audit-event user EVENT-REGISTRATION verification-level "User registered with KYC verification"))
        (ok true)))

(define-public (verify-user-status (user principal))
    (let ((user-data (map-get? verified-users user))
          (current-time (get-stacks-block-info? time (- stacks-block-height u1))))
        (asserts! (is-some user-data) ERR-NOT-VERIFIED)
        (asserts! (get status (unwrap-panic user-data)) ERR-REVOKED)
        (asserts! (> (get expiry (unwrap-panic user-data)) 
            (default-to u0 current-time)) ERR-EXPIRED)
        (ok true)))

(define-public (revoke-verification (user principal))
    (let ((user-data (map-get? verified-users user)))
        (asserts! (is-some (map-get? access-controls tx-sender)) ERR-NOT-AUTHORIZED)
        (asserts! (get can-revoke (default-to {can-verify: false, can-revoke: false} 
            (map-get? access-controls tx-sender))) ERR-NOT-AUTHORIZED)
        (asserts! (is-some user-data) ERR-NOT-VERIFIED)
        (map-set verified-users user 
            (merge (unwrap-panic user-data) {status: false}))
        (unwrap-panic (log-audit-event user EVENT-REVOCATION (get level (unwrap-panic user-data)) "Verification status revoked"))
        (ok true)))

(define-public (update-verification (user principal) (new-proof (buff 64)) (new-expiry uint) (new-level uint))
    (let ((user-data (map-get? verified-users user))
          (current-time (get-stacks-block-info? time (- stacks-block-height u1))))
        (asserts! (is-some (map-get? access-controls tx-sender)) ERR-NOT-AUTHORIZED)
        (asserts! (get can-verify (default-to {can-verify: false, can-revoke: false} 
            (map-get? access-controls tx-sender))) ERR-NOT-AUTHORIZED)
        (asserts! (is-some user-data) ERR-NOT-VERIFIED)
        (asserts! (> new-expiry (default-to u0 current-time)) ERR-INVALID-EXPIRY)
        (asserts! (or (is-eq new-level LEVEL-BASIC) 
                      (or (is-eq new-level LEVEL-STANDARD) 
                          (is-eq new-level LEVEL-PREMIUM))) ERR-INVALID-LEVEL)
        (map-set oracle-proofs new-proof {verified: true, revoked: false})
        (map-set verified-users user 
            {proof: new-proof,
             timestamp: (default-to u0 current-time),
             expiry: new-expiry,
             status: true,
             level: new-level})
        (unwrap-panic (log-audit-event user EVENT-UPDATE new-level "Verification details updated"))
        (ok true)))

(define-read-only (get-user-verification (user principal))
    (ok (map-get? verified-users user)))

(define-read-only (check-proof-validity (proof (buff 64)))
    (ok (map-get? oracle-proofs proof)))

(define-read-only (get-oracle)
    (ok (var-get oracle-address)))

(define-read-only (get-proof-threshold)
    (ok (var-get proof-threshold)))

(define-public (verify-minimum-level (user principal) (required-level uint))
    (let ((user-data (map-get? verified-users user))
          (current-time (get-stacks-block-info? time (- stacks-block-height u1))))
        (asserts! (is-some user-data) ERR-NOT-VERIFIED)
        (asserts! (get status (unwrap-panic user-data)) ERR-REVOKED)
        (asserts! (> (get expiry (unwrap-panic user-data)) 
            (default-to u0 current-time)) ERR-EXPIRED)
        (asserts! (>= (get level (unwrap-panic user-data)) required-level) ERR-INSUFFICIENT-LEVEL)
        (unwrap-panic (log-audit-event user EVENT-LEVEL-CHECK required-level "Level access verified"))
        (ok true)))

(define-read-only (get-user-level (user principal))
    (let ((user-data (map-get? verified-users user)))
        (match user-data
            data (ok (some (get level data)))
            (ok none))))

(define-read-only (check-level-access (user principal) (required-level uint))
    (let ((user-data (map-get? verified-users user))
          (current-time (get-stacks-block-info? time (- stacks-block-height u1))))
        (match user-data
            data (if (and (get status data)
                         (> (get expiry data) (default-to u0 current-time))
                         (>= (get level data) required-level))
                     (ok true)
                     (ok false))
            (ok false))))

(define-read-only (get-audit-log (audit-id uint))
    (ok (map-get? audit-logs audit-id)))

(define-read-only (get-user-audit-count (user principal))
    (ok (default-to u0 (map-get? user-audit-count user))))

(define-read-only (get-total-audit-count)
    (ok (var-get audit-counter)))

(define-read-only (get-audit-logs-by-range (start-id uint) (end-id uint))
    (let ((current-counter (var-get audit-counter)))
        (if (and (<= start-id end-id) (< end-id current-counter))
            (ok {start: start-id, end: end-id, total: current-counter})
            (ok {start: u0, end: u0, total: current-counter}))))

(define-read-only (get-audit-logs-by-user-range (user principal) (start-timestamp uint) (end-timestamp uint))
    (let ((user-count (default-to u0 (map-get? user-audit-count user))))
        (ok {user: user, count: user-count, start: start-timestamp, end: end-timestamp})))

