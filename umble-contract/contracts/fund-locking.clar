;; Smart Contract-Based Fund Locking System
;; Supports time-based and event-based locking with comprehensive audit trails

;; Error codes
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_INVALID_AMOUNT (err u101))
(define-constant ERR_LOCK_NOT_FOUND (err u102))
(define-constant ERR_LOCK_NOT_EXPIRED (err u103))
(define-constant ERR_LOCK_ALREADY_RELEASED (err u104))
(define-constant ERR_INSUFFICIENT_BALANCE (err u105))
(define-constant ERR_INVALID_UNLOCK_CONDITIONS (err u106))
(define-constant ERR_EVENT_NOT_TRIGGERED (err u107))

;; Contract owner
(define-constant CONTRACT_OWNER tx-sender)

;; Lock types
(define-constant LOCK_TYPE_TIME u1)
(define-constant LOCK_TYPE_EVENT u2)
(define-constant LOCK_TYPE_HYBRID u3)

;; Lock status
(define-constant STATUS_ACTIVE u1)
(define-constant STATUS_RELEASED u2)
(define-constant STATUS_CANCELLED u3)

;; Data structures
(define-map fund-locks
  { lock-id: uint }
  {
    owner: principal,
    amount: uint,
    lock-type: uint,
    unlock-block: uint,
    event-condition: (optional (string-ascii 64)),
    status: uint,
    created-at: uint,
    released-at: (optional uint),
    beneficiary: principal
  }
)

;; Event triggers for event-based locks
(define-map event-triggers
  { event-name: (string-ascii 64) }
  {
    triggered: bool,
    trigger-block: uint,
    triggered-by: principal
  }
)

;; Audit trail for all fund movements
(define-map audit-trail
  { transaction-id: uint }
  {
    lock-id: uint,
    action: (string-ascii 32),
    amount: uint,
    actor: principal,
    block-height: uint,
    timestamp: uint
  }
)

;; Counters
(define-data-var lock-counter uint u0)
(define-data-var audit-counter uint u0)

;; Authorized event triggers (who can trigger events)
(define-map authorized-triggers
  { trigger-address: principal }
  { authorized: bool }
)

;; Contract balance tracking
(define-data-var total-locked uint u0)

;; Initialize contract
(begin
  ;; Authorize contract owner as event trigger
  (map-set authorized-triggers { trigger-address: CONTRACT_OWNER } { authorized: true })
)

;; ====================
;; CORE FUNCTIONS
;; ====================

;; Create a time-based lock
(define-public (create-time-lock (amount uint) (unlock-blocks uint) (beneficiary principal))
  (let
    (
      (lock-id (+ (var-get lock-counter) u1))
      (unlock-block (+ block-height unlock-blocks))
    )
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    (asserts! (> unlock-blocks u0) ERR_INVALID_UNLOCK_CONDITIONS)
    
    ;; Transfer funds to contract
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    ;; Create lock record
    (map-set fund-locks
      { lock-id: lock-id }
      {
        owner: tx-sender,
        amount: amount,
        lock-type: LOCK_TYPE_TIME,
        unlock-block: unlock-block,
        event-condition: none,
        status: STATUS_ACTIVE,
        created-at: block-height,
        released-at: none,
        beneficiary: beneficiary
      }
    )
    
    ;; Update counters
    (var-set lock-counter lock-id)
    (var-set total-locked (+ (var-get total-locked) amount))
    
    ;; Add audit trail
    (add-audit-entry lock-id "LOCK_CREATED" amount tx-sender)
    
    (ok lock-id)
  )
)

;; Create an event-based lock
(define-public (create-event-lock (amount uint) (event-name (string-ascii 64)) (beneficiary principal))
  (let
    (
      (lock-id (+ (var-get lock-counter) u1))
    )
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    (asserts! (> (len event-name) u0) ERR_INVALID_UNLOCK_CONDITIONS)
    
    ;; Transfer funds to contract
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    ;; Create lock record
    (map-set fund-locks
      { lock-id: lock-id }
      {
        owner: tx-sender,
        amount: amount,
        lock-type: LOCK_TYPE_EVENT,
        unlock-block: u0,
        event-condition: (some event-name),
        status: STATUS_ACTIVE,
        created-at: block-height,
        released-at: none,
        beneficiary: beneficiary
      }
    )
    
    ;; Update counters
    (var-set lock-counter lock-id)
    (var-set total-locked (+ (var-get total-locked) amount))
    
    ;; Add audit trail
    (add-audit-entry lock-id "EVENT_LOCK_CREATED" amount tx-sender)
    
    (ok lock-id)
  )
)

;; Create a hybrid lock (both time and event conditions)
(define-public (create-hybrid-lock (amount uint) (unlock-blocks uint) (event-name (string-ascii 64)) (beneficiary principal))
  (let
    (
      (lock-id (+ (var-get lock-counter) u1))
      (unlock-block (+ block-height unlock-blocks))
    )
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    (asserts! (> unlock-blocks u0) ERR_INVALID_UNLOCK_CONDITIONS)
    (asserts! (> (len event-name) u0) ERR_INVALID_UNLOCK_CONDITIONS)
    
    ;; Transfer funds to contract
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    ;; Create lock record
    (map-set fund-locks
      { lock-id: lock-id }
      {
        owner: tx-sender,
        amount: amount,
        lock-type: LOCK_TYPE_HYBRID,
        unlock-block: unlock-block,
        event-condition: (some event-name),
        status: STATUS_ACTIVE,
        created-at: block-height,
        released-at: none,
        beneficiary: beneficiary
      }
    )
    
    ;; Update counters
    (var-set lock-counter lock-id)
    (var-set total-locked (+ (var-get total-locked) amount))
    
    ;; Add audit trail
    (add-audit-entry lock-id "HYBRID_LOCK_CREATED" amount tx-sender)
    
    (ok lock-id)
  )
)

;; Release funds from a lock
(define-public (release-funds (lock-id uint))
  (let
    (
      (lock-data (unwrap! (map-get? fund-locks { lock-id: lock-id }) ERR_LOCK_NOT_FOUND))
      (lock-type (get lock-type lock-data))
      (amount (get amount lock-data))
      (beneficiary (get beneficiary lock-data))
    )
    ;; Verify caller is owner or beneficiary
    (asserts! (or (is-eq tx-sender (get owner lock-data)) 
                  (is-eq tx-sender beneficiary)) ERR_NOT_AUTHORIZED)
    
    ;; Check if lock is active
    (asserts! (is-eq (get status lock-data) STATUS_ACTIVE) ERR_LOCK_ALREADY_RELEASED)
    
    ;; Check unlock conditions based on lock type
    (asserts! (is-unlocked lock-data) ERR_LOCK_NOT_EXPIRED)
    
    ;; Update lock status
    (map-set fund-locks
      { lock-id: lock-id }
      (merge lock-data { 
        status: STATUS_RELEASED,
        released-at: (some block-height)
      })
    )
    
    ;; Transfer funds to beneficiary
    (try! (as-contract (stx-transfer? amount tx-sender beneficiary)))
    
    ;; Update total locked
    (var-set total-locked (- (var-get total-locked) amount))
    
    ;; Add audit trail
    (add-audit-entry lock-id "FUNDS_RELEASED" amount tx-sender)
    
    (ok true)
  )
)

;; Trigger an event (only authorized addresses can do this)
(define-public (trigger-event (event-name (string-ascii 64)))
  (begin
    ;; Check if caller is authorized
    (asserts! (is-authorized-trigger tx-sender) ERR_NOT_AUTHORIZED)
    
    ;; Set event as triggered
    (map-set event-triggers
      { event-name: event-name }
      {
        triggered: true,
        trigger-block: block-height,
        triggered-by: tx-sender
      }
    )
    
    (ok true)
  )
)

;; ====================
;; HELPER FUNCTIONS
;; ====================

;; Check if a lock can be unlocked
(define-private (is-unlocked (lock-data (tuple (owner principal) (amount uint) (lock-type uint) (unlock-block uint) (event-condition (optional (string-ascii 64))) (status uint) (created-at uint) (released-at (optional uint)) (beneficiary principal))))
  (let
    (
      (lock-type (get lock-type lock-data))
      (unlock-block (get unlock-block lock-data))
      (event-condition (get event-condition lock-data))
    )
    (if (is-eq lock-type LOCK_TYPE_TIME)
      ;; Time-based lock
      (>= block-height unlock-block)
      (if (is-eq lock-type LOCK_TYPE_EVENT)
        ;; Event-based lock
        (match event-condition
          event-name (is-event-triggered event-name)
          false
        )
        ;; Hybrid lock (both conditions must be met)
        (and 
          (>= block-height unlock-block)
          (match event-condition
            event-name (is-event-triggered event-name)
            false
          )
        )
      )
    )
  )
)

;; Check if an event has been triggered
(define-private (is-event-triggered (event-name (string-ascii 64)))
  (match (map-get? event-triggers { event-name: event-name })
    trigger-data (get triggered trigger-data)
    false
  )
)

;; Check if address is authorized to trigger events
(define-private (is-authorized-trigger (address principal))
  (match (map-get? authorized-triggers { trigger-address: address })
    auth-data (get authorized auth-data)
    false
  )
)

;; Add audit trail entry
(define-private (add-audit-entry (lock-id uint) (action (string-ascii 32)) (amount uint) (actor principal))
  (let
    (
      (audit-id (+ (var-get audit-counter) u1))
    )
    (map-set audit-trail
      { transaction-id: audit-id }
      {
        lock-id: lock-id,
        action: action,
        amount: amount,
        actor: actor,
        block-height: block-height,
        timestamp: block-height ;; Using block-height as timestamp proxy
      }
    )
    (var-set audit-counter audit-id)
  )
)

;; ====================
;; ADMIN FUNCTIONS
;; ====================

;; Add authorized event trigger
(define-public (add-authorized-trigger (address principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (map-set authorized-triggers
      { trigger-address: address }
      { authorized: true }
    )
    (ok true)
  )
)

;; Remove authorized event trigger
(define-public (remove-authorized-trigger (address principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (map-set authorized-triggers
      { trigger-address: address }
      { authorized: false }
    )
    (ok true)
  )
)

;; Emergency cancel lock (only owner)
(define-public (emergency-cancel-lock (lock-id uint))
  (let
    (
      (lock-data (unwrap! (map-get? fund-locks { lock-id: lock-id }) ERR_LOCK_NOT_FOUND))
      (amount (get amount lock-data))
      (owner (get owner lock-data))
    )
    ;; Only contract owner or lock owner can cancel
    (asserts! (or (is-eq tx-sender CONTRACT_OWNER) 
                  (is-eq tx-sender owner)) ERR_NOT_AUTHORIZED)
    
    ;; Check if lock is active
    (asserts! (is-eq (get status lock-data) STATUS_ACTIVE) ERR_LOCK_ALREADY_RELEASED)
    
    ;; Update lock status
    (map-set fund-locks
      { lock-id: lock-id }
      (merge lock-data { 
        status: STATUS_CANCELLED,
        released-at: (some block-height)
      })
    )
    
    ;; Return funds to original owner
    (try! (as-contract (stx-transfer? amount tx-sender owner)))
    
    ;; Update total locked
    (var-set total-locked (- (var-get total-locked) amount))
    
    ;; Add audit trail
    (add-audit-entry lock-id "LOCK_CANCELLED" amount tx-sender)
    
    (ok true)
  )
)

;; ====================
;; READ-ONLY FUNCTIONS
;; ====================

;; Get lock details
(define-read-only (get-lock-details (lock-id uint))
  (map-get? fund-locks { lock-id: lock-id })
)

;; Get event trigger status
(define-read-only (get-event-status (event-name (string-ascii 64)))
  (map-get? event-triggers { event-name: event-name })
)

;; Get audit trail entry
(define-read-only (get-audit-entry (transaction-id uint))
  (map-get? audit-trail { transaction-id: transaction-id })
)

;; Get total locked funds
(define-read-only (get-total-locked)
  (var-get total-locked)
)

;; Get current lock counter
(define-read-only (get-lock-counter)
  (var-get lock-counter)
)

;; Check if lock can be released
(define-read-only (can-release-lock (lock-id uint))
  (match (map-get? fund-locks { lock-id: lock-id })
    lock-data (and 
                (is-eq (get status lock-data) STATUS_ACTIVE)
                (is-unlocked lock-data)
              )
    false
  )
)

;; Get locks by owner (helper for front-end)
(define-read-only (is-lock-owner (lock-id uint) (address principal))
  (match (map-get? fund-locks { lock-id: lock-id })
    lock-data (is-eq (get owner lock-data) address)
    false
  )
)