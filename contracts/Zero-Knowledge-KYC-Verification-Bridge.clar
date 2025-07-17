(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PROOF (err u101))
(define-constant ERR-ALREADY-VERIFIED (err u102))
(define-constant ERR-NOT-VERIFIED (err u103))
(define-constant ERR-EXPIRED (err u104))
(define-constant ERR-REVOKED (err u105))
(define-constant ERR-INVALID-EXPIRY (err u106))

(define-data-var contract-owner principal tx-sender)
(define-data-var oracle-address principal tx-sender)
(define-data-var proof-threshold uint u5)

(define-map verified-users 
    principal 
    {proof: (buff 64), 
     timestamp: uint,
     expiry: uint,
     status: bool})

(define-map oracle-proofs 
    (buff 64) 
    {verified: bool, 
     revoked: bool})

(define-map access-controls
    principal 
    {can-verify: bool,
     can-revoke: bool})

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

(define-public (register-proof (user principal) (proof (buff 64)) (expiry uint))
    (let ((current-time (get-stacks-block-info? time (- stacks-block-height u1))))
        (asserts! (is-some (map-get? access-controls tx-sender)) ERR-NOT-AUTHORIZED)
        (asserts! (get can-verify (default-to {can-verify: false, can-revoke: false} 
            (map-get? access-controls tx-sender))) ERR-NOT-AUTHORIZED)
        (asserts! (> expiry (default-to u0 current-time)) ERR-INVALID-EXPIRY)
        (asserts! (is-none (map-get? verified-users user)) ERR-ALREADY-VERIFIED)
        (map-set oracle-proofs proof {verified: true, revoked: false})
        (ok (map-set verified-users user 
            {proof: proof,
             timestamp: (default-to u0 current-time),
             expiry: expiry,
             status: true}))))

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
        (ok true)))

(define-public (update-verification (user principal) (new-proof (buff 64)) (new-expiry uint))
    (let ((user-data (map-get? verified-users user))
          (current-time (get-stacks-block-info? time (- stacks-block-height u1))))
        (asserts! (is-some (map-get? access-controls tx-sender)) ERR-NOT-AUTHORIZED)
        (asserts! (get can-verify (default-to {can-verify: false, can-revoke: false} 
            (map-get? access-controls tx-sender))) ERR-NOT-AUTHORIZED)
        (asserts! (is-some user-data) ERR-NOT-VERIFIED)
        (asserts! (> new-expiry (default-to u0 current-time)) ERR-INVALID-EXPIRY)
        (map-set oracle-proofs new-proof {verified: true, revoked: false})
        (ok (map-set verified-users user 
            {proof: new-proof,
             timestamp: (default-to u0 current-time),
             expiry: new-expiry,
             status: true}))))

(define-read-only (get-user-verification (user principal))
    (ok (map-get? verified-users user)))

(define-read-only (check-proof-validity (proof (buff 64)))
    (ok (map-get? oracle-proofs proof)))

(define-read-only (get-oracle)
    (ok (var-get oracle-address)))

(define-read-only (get-proof-threshold)
    (ok (var-get proof-threshold)))

