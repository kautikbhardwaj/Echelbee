<?php
// send_email.php - Email handler for Echelbee website forms

// Prevent direct access
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(403);
    die('Direct access not permitted');
}

// Set response header
header('Content-Type: application/json');

// Configuration
$to_email = 'support@echelbee.in';
$from_email = 'noreply@echelbee.in'; // Change this to a valid email on your domain

// Security: Basic sanitization function
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Initialize response
$response = array(
    'success' => false,
    'message' => ''
);

try {
    // Check if this is a service call form or contact form
    $form_type = isset($_POST['form_type']) ? sanitize_input($_POST['form_type']) : 'contact';
    
    if ($form_type === 'service_call') {
        // Service Call Form
        
        // Validate required fields
        if (empty($_POST['customerName']) || empty($_POST['customerEmail']) || 
            empty($_POST['contactNumber']) || empty($_POST['customerLocation']) || 
            empty($_POST['issueDescription'])) {
            throw new Exception('All fields are required');
        }
        
        // Get and sanitize form data
        $customer_name = sanitize_input($_POST['customerName']);
        $customer_email = sanitize_input($_POST['customerEmail']);
        $contact_number = sanitize_input($_POST['contactNumber']);
        $customer_location = sanitize_input($_POST['customerLocation']);
        $issue_description = sanitize_input($_POST['issueDescription']);
        
        // Validate email format
        if (!filter_var($customer_email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception('Invalid email format');
        }
        
        // Email subject
        $subject = "Service Call Request from " . $customer_name;
        
        // Email body (HTML format)
        $message = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #0066FF; color: white; padding: 20px; text-align: center; }
                .content { background-color: #f5f7fa; padding: 20px; margin-top: 20px; }
                .field { margin-bottom: 15px; }
                .label { font-weight: bold; color: #0066FF; }
                .value { margin-top: 5px; padding: 10px; background-color: white; border-left: 3px solid #0066FF; }
                .footer { margin-top: 20px; padding: 15px; background-color: #0A1929; color: white; text-align: center; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h2>New Service Call Request</h2>
                </div>
                <div class='content'>
                    <div class='field'>
                        <div class='label'>Customer Name:</div>
                        <div class='value'>" . $customer_name . "</div>
                    </div>
                    <div class='field'>
                        <div class='label'>Email Address:</div>
                        <div class='value'>" . $customer_email . "</div>
                    </div>
                    <div class='field'>
                        <div class='label'>Contact Number:</div>
                        <div class='value'>" . $contact_number . "</div>
                    </div>
                    <div class='field'>
                        <div class='label'>Location:</div>
                        <div class='value'>" . $customer_location . "</div>
                    </div>
                    <div class='field'>
                        <div class='label'>Issue Description:</div>
                        <div class='value'>" . nl2br($issue_description) . "</div>
                    </div>
                </div>
                <div class='footer'>
                    <p>This is an automated message from ECH EL BEE PIXEL 2 PAPER website</p>
                    <p>299 (Basement) Mandir Marg, Mahaveer Nagar, Durgapura, Jaipur - 302018</p>
                </div>
            </div>
        </body>
        </html>
        ";
        
    } else {
        // Contact Form
        
        // Validate required fields
        if (empty($_POST['name']) || empty($_POST['email']) || empty($_POST['message'])) {
            throw new Exception('Name, email, and message are required');
        }
        
        // Get and sanitize form data
        $name = sanitize_input($_POST['name']);
        $email = sanitize_input($_POST['email']);
        $phone = isset($_POST['phone']) ? sanitize_input($_POST['phone']) : 'Not provided';
        $message_text = sanitize_input($_POST['message']);
        
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception('Invalid email format');
        }
        
        // Email subject
        $subject = "Contact Form Submission from " . $name;
        
        // Email body (HTML format)
        $message = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #0066FF; color: white; padding: 20px; text-align: center; }
                .content { background-color: #f5f7fa; padding: 20px; margin-top: 20px; }
                .field { margin-bottom: 15px; }
                .label { font-weight: bold; color: #0066FF; }
                .value { margin-top: 5px; padding: 10px; background-color: white; border-left: 3px solid #0066FF; }
                .footer { margin-top: 20px; padding: 15px; background-color: #0A1929; color: white; text-align: center; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h2>New Contact Form Submission</h2>
                </div>
                <div class='content'>
                    <div class='field'>
                        <div class='label'>Name:</div>
                        <div class='value'>" . $name . "</div>
                    </div>
                    <div class='field'>
                        <div class='label'>Email:</div>
                        <div class='value'>" . $email . "</div>
                    </div>
                    <div class='field'>
                        <div class='label'>Phone:</div>
                        <div class='value'>" . $phone . "</div>
                    </div>
                    <div class='field'>
                        <div class='label'>Message:</div>
                        <div class='value'>" . nl2br($message_text) . "</div>
                    </div>
                </div>
                <div class='footer'>
                    <p>This is an automated message from ECH EL BEE PIXEL 2 PAPER website</p>
                    <p>299 (Basement) Mandir Marg, Mahaveer Nagar, Durgapura, Jaipur - 302018</p>
                </div>
            </div>
        </body>
        </html>
        ";
    }
    
    // Email headers
    $headers = array();
    $headers[] = "MIME-Version: 1.0";
    $headers[] = "Content-type: text/html; charset=UTF-8";
    $headers[] = "From: ECH EL BEE <" . $from_email . ">";
    $headers[] = "Reply-To: " . ($form_type === 'service_call' ? $customer_email : $email);
    $headers[] = "X-Mailer: PHP/" . phpversion();
    
    // Send email
    $mail_sent = mail($to_email, $subject, $message, implode("\r\n", $headers));
    
    if ($mail_sent) {
        $response['success'] = true;
        $response['message'] = $form_type === 'service_call' 
            ? 'Service call request submitted successfully! We will contact you soon.' 
            : 'Thank you for your message! We will get back to you soon.';
    } else {
        throw new Exception('Failed to send email. Please try again later.');
    }
    
} catch (Exception $e) {
    $response['success'] = false;
    $response['message'] = $e->getMessage();
}

// Return JSON response
echo json_encode($response);
exit;
?>
