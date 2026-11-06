PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    password_hash TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
);
CREATE TABLE IF NOT EXISTS festival_categories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);
CREATE TABLE IF NOT EXISTS organizers (
    organizer_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    organization_name TEXT NOT NULL,
    contact_person TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    approval_status TEXT NOT NULL DEFAULT 'Pending',
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS festivals (
    festival_id INTEGER PRIMARY KEY AUTOINCREMENT,
    festival_name TEXT NOT NULL,
    description TEXT,
    theme TEXT,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    location TEXT NOT NULL,
    category_id INTEGER NOT NULL,
    organizer_id INTEGER,
    status TEXT NOT NULL DEFAULT 'Upcoming',
    budget REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(category_id) REFERENCES festival_categories(category_id),
    FOREIGN KEY(organizer_id) REFERENCES organizers(organizer_id)
);
CREATE TABLE IF NOT EXISTS committees (
    committee_id INTEGER PRIMARY KEY AUTOINCREMENT,
    festival_id INTEGER NOT NULL,
    committee_name TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY(festival_id) REFERENCES festivals(festival_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS committee_members (
    member_id INTEGER PRIMARY KEY AUTOINCREMENT,
    committee_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    designation TEXT,
    joined_date TEXT,
    FOREIGN KEY(committee_id) REFERENCES committees(committee_id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS event_categories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);
CREATE TABLE IF NOT EXISTS event_coordinators (
    coordinator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    festival_id INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    coordinator_id INTEGER,
    event_name TEXT NOT NULL,
    description TEXT,
    rules TEXT,
    eligibility_criteria TEXT,
    max_participants INTEGER NOT NULL DEFAULT 0,
    min_participants INTEGER NOT NULL DEFAULT 0,
    registration_deadline TEXT,
    status TEXT NOT NULL DEFAULT 'Draft',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(festival_id) REFERENCES festivals(festival_id) ON DELETE CASCADE,
    FOREIGN KEY(category_id) REFERENCES event_categories(category_id),
    FOREIGN KEY(coordinator_id) REFERENCES event_coordinators(coordinator_id)
);
CREATE TABLE IF NOT EXISTS venues (
    venue_id INTEGER PRIMARY KEY AUTOINCREMENT,
    venue_name TEXT NOT NULL UNIQUE,
    location TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    venue_type TEXT,
    facilities TEXT,
    status TEXT NOT NULL DEFAULT 'Available'
);
CREATE TABLE IF NOT EXISTS venue_facilities (
    facility_id INTEGER PRIMARY KEY AUTOINCREMENT,
    venue_id INTEGER NOT NULL,
    facility_name TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY(venue_id) REFERENCES venues(venue_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS event_schedules (
    schedule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE,
    venue_id INTEGER NOT NULL,
    event_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Scheduled',
    FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE,
    FOREIGN KEY(venue_id) REFERENCES venues(venue_id)
);
CREATE TABLE IF NOT EXISTS resources (
    resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_name TEXT NOT NULL UNIQUE,
    description TEXT,
    quantity_total INTEGER NOT NULL DEFAULT 0,
    quantity_available INTEGER NOT NULL DEFAULT 0,
    resource_type TEXT,
    status TEXT NOT NULL DEFAULT 'Available'
);
CREATE TABLE IF NOT EXISTS event_resources (
    event_resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    quantity_required INTEGER NOT NULL DEFAULT 1,
    quantity_allocated INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Requested',
    FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE,
    FOREIGN KEY(resource_id) REFERENCES resources(resource_id)
);
CREATE TABLE IF NOT EXISTS participants (
    participant_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    dob TEXT,
    college_name TEXT,
    department TEXT,
    address TEXT,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS ticket_types (
    ticket_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    type_name TEXT NOT NULL,
    price REAL NOT NULL DEFAULT 0,
    total_tickets INTEGER NOT NULL DEFAULT 0,
    available_tickets INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS registrations (
    registration_id INTEGER PRIMARY KEY AUTOINCREMENT,
    participant_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    registration_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    payment_status TEXT NOT NULL DEFAULT 'Pending',
    amount_paid REAL NOT NULL DEFAULT 0,
    FOREIGN KEY(participant_id) REFERENCES participants(participant_id),
    FOREIGN KEY(event_id) REFERENCES events(event_id),
    UNIQUE(participant_id,event_id)
);
CREATE TABLE IF NOT EXISTS tickets (
    ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_id INTEGER NOT NULL,
    ticket_type_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price REAL NOT NULL DEFAULT 0,
    total_price REAL NOT NULL DEFAULT 0,
    discount REAL NOT NULL DEFAULT 0,
    final_amount REAL NOT NULL DEFAULT 0,
    ticket_no TEXT NOT NULL UNIQUE,
    qr_code TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'Active',
    FOREIGN KEY(registration_id) REFERENCES registrations(registration_id) ON DELETE CASCADE,
    FOREIGN KEY(ticket_type_id) REFERENCES ticket_types(ticket_type_id)
);
CREATE TABLE IF NOT EXISTS payment_methods (
    method_id INTEGER PRIMARY KEY AUTOINCREMENT,
    method_name TEXT NOT NULL UNIQUE,
    description TEXT
);
CREATE TABLE IF NOT EXISTS payments (
    payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    payment_method_id INTEGER,
    transaction_id TEXT UNIQUE,
    payment_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Success',
    refund_id INTEGER,
    FOREIGN KEY(registration_id) REFERENCES registrations(registration_id),
    FOREIGN KEY(payment_method_id) REFERENCES payment_methods(method_id)
);
CREATE TABLE IF NOT EXISTS refunds (
    refund_id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_id INTEGER,
    refund_amount REAL NOT NULL,
    refund_date TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'Processed',
    FOREIGN KEY(payment_id) REFERENCES payments(payment_id)
);
CREATE TABLE IF NOT EXISTS attendance (
    attendance_id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_id INTEGER NOT NULL UNIQUE,
    checkin_time TEXT,
    checkout_time TEXT,
    status TEXT NOT NULL DEFAULT 'Absent',
    scanned_by INTEGER,
    FOREIGN KEY(registration_id) REFERENCES registrations(registration_id) ON DELETE CASCADE,
    FOREIGN KEY(scanned_by) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS certificates (
    certificate_id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_id INTEGER NOT NULL UNIQUE,
    certificate_no TEXT NOT NULL UNIQUE,
    issue_date TEXT,
    status TEXT NOT NULL DEFAULT 'Eligible',
    certificate_url TEXT,
    FOREIGN KEY(registration_id) REFERENCES registrations(registration_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS coupons (
    coupon_id INTEGER PRIMARY KEY AUTOINCREMENT,
    coupon_code TEXT NOT NULL UNIQUE,
    discount_percent REAL NOT NULL,
    valid_from TEXT,
    valid_to TEXT,
    usage_limit INTEGER DEFAULT 0,
    usage_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'Active'
);
CREATE TABLE IF NOT EXISTS volunteers (
    volunteer_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    skills TEXT,
    availability_status TEXT DEFAULT 'Available',
    joined_date TEXT DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Active',
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS volunteer_assignments (
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    volunteer_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    role TEXT,
    duty_description TEXT,
    shift_date TEXT,
    start_time TEXT,
    end_time TEXT,
    status TEXT DEFAULT 'Assigned',
    FOREIGN KEY(volunteer_id) REFERENCES volunteers(volunteer_id) ON DELETE CASCADE,
    FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS volunteer_attendance (
    attendance_id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    checkin_time TEXT,
    checkout_time TEXT,
    status TEXT DEFAULT 'Absent',
    remarks TEXT,
    FOREIGN KEY(assignment_id) REFERENCES volunteer_assignments(assignment_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS volunteer_skills (
    skill_id INTEGER PRIMARY KEY AUTOINCREMENT,
    volunteer_id INTEGER NOT NULL,
    skill_name TEXT NOT NULL,
    level TEXT,
    FOREIGN KEY(volunteer_id) REFERENCES volunteers(volunteer_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sponsors (
    sponsor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    company_name TEXT NOT NULL,
    contact_person TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    website TEXT,
    status TEXT DEFAULT 'Active',
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS sponsorship_packages (
    package_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    amount REAL NOT NULL,
    benefits TEXT,
    description TEXT,
    status TEXT DEFAULT 'Active'
);
CREATE TABLE IF NOT EXISTS sponsorships (
    sponsorship_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sponsor_id INTEGER NOT NULL,
    festival_id INTEGER NOT NULL,
    package_id INTEGER,
    amount REAL NOT NULL,
    start_date TEXT,
    end_date TEXT,
    status TEXT DEFAULT 'Active',
    agreement_file TEXT,
    FOREIGN KEY(sponsor_id) REFERENCES sponsors(sponsor_id),
    FOREIGN KEY(festival_id) REFERENCES festivals(festival_id),
    FOREIGN KEY(package_id) REFERENCES sponsorship_packages(package_id)
);
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comments TEXT,
    feedback_date TEXT NOT NULL,
    status TEXT DEFAULT 'New',
    FOREIGN KEY(event_id) REFERENCES events(event_id),
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS complaints (
    complaint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_id INTEGER,
    complaint_type TEXT,
    description TEXT,
    status TEXT DEFAULT 'Open',
    action_taken TEXT,
    action_date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(user_id),
    FOREIGN KEY(event_id) REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT,
    event_id INTEGER,
    sent_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Sent',
    FOREIGN KEY(user_id) REFERENCES users(user_id),
    FOREIGN KEY(event_id) REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS emergency_contacts (
    contact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT,
    phone TEXT,
    email TEXT,
    assigned_event_id INTEGER,
    status TEXT DEFAULT 'Active',
    FOREIGN KEY(assigned_event_id) REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    reported_by INTEGER,
    incident_type TEXT,
    description TEXT,
    incident_date TEXT,
    action_taken TEXT,
    location TEXT,
    severity TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'Open',
    FOREIGN KEY(event_id) REFERENCES events(event_id),
    FOREIGN KEY(reported_by) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS reports (
    report_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_name TEXT NOT NULL,
    report_type TEXT,
    generated_by INTEGER,
    generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    file_path TEXT,
    FOREIGN KEY(generated_by) REFERENCES users(user_id)
);

CREATE INDEX IF NOT EXISTS idx_events_festival ON events(festival_id);
CREATE INDEX IF NOT EXISTS idx_schedule_venue_date ON event_schedules(venue_id,event_date);
CREATE INDEX IF NOT EXISTS idx_registration_event ON registrations(event_id);
CREATE INDEX IF NOT EXISTS idx_registration_participant ON registrations(participant_id);
CREATE INDEX IF NOT EXISTS idx_payments_registration ON payments(registration_id);
CREATE INDEX IF NOT EXISTS idx_feedback_event ON feedback(event_id);

INSERT OR IGNORE INTO payment_methods(method_name,description) VALUES
('Cash','Cash payment'),('Card','Debit/Credit Card'),('UPI','UPI payment'),('Net Banking','Internet banking'),('Razorpay','Razorpay online payment'),('Demo','Simulated demo transaction; no money charged');

-- EFMS upgrade: operational, parking, finance, safety and audit extensions
CREATE TABLE IF NOT EXISTS parking_zones (parking_zone_id INTEGER PRIMARY KEY AUTOINCREMENT, zone_name TEXT NOT NULL UNIQUE, location TEXT NOT NULL, vehicle_type TEXT NOT NULL DEFAULT 'Any', capacity INTEGER NOT NULL CHECK(capacity>=0), accessible_spaces INTEGER NOT NULL DEFAULT 0 CHECK(accessible_spaces>=0), status TEXT NOT NULL DEFAULT 'Open', notes TEXT);
CREATE TABLE IF NOT EXISTS parking_allocations (parking_allocation_id INTEGER PRIMARY KEY AUTOINCREMENT, parking_zone_id INTEGER NOT NULL, user_id INTEGER, event_id INTEGER, visitor_name TEXT NOT NULL, vehicle_number TEXT NOT NULL, vehicle_type TEXT NOT NULL, pass_code TEXT NOT NULL UNIQUE, allocated_at TEXT NOT NULL, entry_time TEXT, exit_time TEXT, status TEXT NOT NULL DEFAULT 'Reserved', fee REAL NOT NULL DEFAULT 0, accessible_need INTEGER NOT NULL DEFAULT 0, notes TEXT, FOREIGN KEY(parking_zone_id) REFERENCES parking_zones(parking_zone_id), FOREIGN KEY(user_id) REFERENCES users(user_id), FOREIGN KEY(event_id) REFERENCES events(event_id));
CREATE INDEX IF NOT EXISTS idx_parking_zone_active ON parking_allocations(parking_zone_id,status);
CREATE TABLE IF NOT EXISTS budget_expenses (expense_id INTEGER PRIMARY KEY AUTOINCREMENT, festival_id INTEGER NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, amount REAL NOT NULL CHECK(amount>=0), expense_date TEXT NOT NULL, vendor TEXT, recorded_by INTEGER, status TEXT NOT NULL DEFAULT 'Approved', FOREIGN KEY(festival_id) REFERENCES festivals(festival_id), FOREIGN KEY(recorded_by) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS event_approvals (approval_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL UNIQUE, submitted_by INTEGER, status TEXT NOT NULL DEFAULT 'Pending', reviewer_id INTEGER, review_note TEXT, submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT, FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE, FOREIGN KEY(submitted_by) REFERENCES users(user_id), FOREIGN KEY(reviewer_id) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS volunteer_shifts (shift_id INTEGER PRIMARY KEY AUTOINCREMENT, volunteer_id INTEGER NOT NULL, event_id INTEGER NOT NULL, shift_date TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL, duty TEXT NOT NULL, location TEXT, status TEXT NOT NULL DEFAULT 'Assigned', notes TEXT, FOREIGN KEY(volunteer_id) REFERENCES volunteers(volunteer_id) ON DELETE CASCADE, FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS waitlist (waitlist_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, user_id INTEGER NOT NULL, requested_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Waiting', notes TEXT, FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(user_id), UNIQUE(event_id,user_id));
CREATE TABLE IF NOT EXISTS lost_found (item_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, item_type TEXT NOT NULL, item_name TEXT NOT NULL, description TEXT, location_found TEXT, reported_by INTEGER, contact_info TEXT, status TEXT NOT NULL DEFAULT 'Reported', claimed_by TEXT, reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT, FOREIGN KEY(event_id) REFERENCES events(event_id), FOREIGN KEY(reported_by) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS announcements (announcement_id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, message TEXT NOT NULL, audience TEXT NOT NULL DEFAULT 'All', event_id INTEGER, created_by INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, status TEXT NOT NULL DEFAULT 'Published', FOREIGN KEY(event_id) REFERENCES events(event_id), FOREIGN KEY(created_by) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS audit_logs (audit_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT, details TEXT, ip_address TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS accessibility_crowd_checks (check_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, check_type TEXT NOT NULL, location TEXT, observed_count INTEGER NOT NULL DEFAULT 0, safe_limit INTEGER NOT NULL DEFAULT 0, accessibility_note TEXT, status TEXT NOT NULL DEFAULT 'Normal', reported_by INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(event_id) REFERENCES events(event_id), FOREIGN KEY(reported_by) REFERENCES users(user_id));
CREATE TABLE IF NOT EXISTS notification_reads (notification_read_id INTEGER PRIMARY KEY AUTOINCREMENT, notification_id INTEGER NOT NULL, user_id INTEGER NOT NULL, read_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(notification_id) REFERENCES notifications(notification_id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(user_id), UNIQUE(notification_id,user_id));

-- Self-service portal extensions
CREATE TABLE IF NOT EXISTS organizer_profiles (profile_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, organization_name TEXT NOT NULL, bio TEXT, website TEXT, address TEXT, verified_status TEXT NOT NULL DEFAULT 'Pending', FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS participant_profiles (profile_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, date_of_birth TEXT, college TEXT, department TEXT, address TEXT, emergency_contact TEXT, FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS volunteer_profiles (profile_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, bio TEXT, date_of_birth TEXT, address TEXT, education TEXT, experience TEXT, skills TEXT, availability TEXT, emergency_contact TEXT, FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS volunteer_applications (application_id INTEGER PRIMARY KEY AUTOINCREMENT, volunteer_id INTEGER NOT NULL, event_id INTEGER NOT NULL, message TEXT, status TEXT NOT NULL DEFAULT 'Pending', applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_by INTEGER, review_note TEXT, FOREIGN KEY(volunteer_id) REFERENCES volunteers(volunteer_id) ON DELETE CASCADE, FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE, FOREIGN KEY(reviewed_by) REFERENCES users(user_id), UNIQUE(volunteer_id,event_id));
CREATE TABLE IF NOT EXISTS direct_messages (message_id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL, event_id INTEGER, subject TEXT NOT NULL, body TEXT NOT NULL, sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, read_at TEXT, FOREIGN KEY(sender_id) REFERENCES users(user_id) ON DELETE CASCADE, FOREIGN KEY(recipient_id) REFERENCES users(user_id) ON DELETE CASCADE, FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE SET NULL);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON direct_messages(recipient_id,sent_at);
CREATE TABLE IF NOT EXISTS ticket_checkins (checkin_id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL UNIQUE, checkin_time TEXT NOT NULL, scanned_by INTEGER, status TEXT NOT NULL DEFAULT 'Present', notes TEXT, FOREIGN KEY(ticket_id) REFERENCES tickets(ticket_id) ON DELETE CASCADE, FOREIGN KEY(scanned_by) REFERENCES users(user_id));
