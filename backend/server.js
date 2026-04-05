const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs'); // Thêm thư viện đọc/ghi file có sẵn của Node.js
const { generateKeys, signDocument, verifySignature } = require('./chukyso');

const app = express();
app.use(cors({ origin: '*' })); 
app.use(express.json({ limit: '10mb' })); 
const upload = multer({ storage: multer.memoryStorage() });

// ==========================================
// CƠ SỞ DỮ LIỆU BẰNG FILE JSON
// ==========================================
const DB_FILE = './database.json';

// Hàm 1: Đọc dữ liệu từ file khi khởi động
function loadDatabase() {
    try {
        // Kiểm tra xem file có tồn tại chưa
        if (fs.existsSync(DB_FILE)) {
            const fileData = fs.readFileSync(DB_FILE, 'utf8');
            return JSON.parse(fileData);
        }
    } catch (error) {
        console.error("Lỗi khi đọc file database:", error);
    }
    return {}; // Nếu file chưa có thì tạo database rỗng
}

// Hàm 2: Ghi dữ liệu xuống file
function saveDatabase(data) {
    try {
        // Biến Object thành chuỗi JSON đẹp mắt và lưu vào file
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 4), 'utf8');
    } catch (error) {
        console.error("Lỗi khi lưu file database:", error);
    }
}

// Khởi tạo Database từ file
let userDatabase = loadDatabase();

// ==========================================
// API 1: ĐĂNG KÝ TÀI KHOẢN (Đã cập nhật lưu file)
// ==========================================
app.post('/api/register', (req, res) => {
    try {
        const { username, password, signatureImage } = req.body;

        if (userDatabase[username]) {
            return res.status(400).json({ success: false, message: 'Mã nhân viên đã tồn tại!' });
        }

        const keys = generateKeys();
        
        userDatabase[username] = {
            password: password,
            signatureImage: signatureImage,
            privateKey: keys.privateKey,
            publicKey: keys.publicKey
        };

        // GỌI HÀM LƯU XUỐNG FILE NGAY SAU KHI TẠO TÀI KHOẢN
        saveDatabase(userDatabase);

        res.json({ 
            success: true, 
            message: 'Đăng ký và khởi tạo chữ ký số thành công!',
            publicKey: keys.publicKey 
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi hệ thống khi đăng ký.' });
    }
});

// ==========================================
// API 2: ĐĂNG NHẬP (Giữ nguyên)
// ==========================================
app.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const user = userDatabase[username];
        
        if (!user || user.password !== password) {
            return res.status(401).json({ success: false, message: 'Sai mã nhân viên hoặc mật khẩu!' });
        }

        res.json({ 
            success: true, 
            message: 'Đăng nhập thành công!',
            signatureImage: user.signatureImage,
            publicKey: user.publicKey
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi hệ thống khi đăng nhập.' });
    }
});

// ==========================================
// API 3: KÝ DUYỆT VĂN BẢN (Giữ nguyên)
// ==========================================
app.post('/api/sign', upload.single('document'), (req, res) => {
    try {
        const documentBuffer = req.file.buffer;
        const username = req.body.username;
        const password = req.body.password;
        
        const user = userDatabase[username];

        if (!user || user.password !== password) {
            return res.status(401).json({ success: false, message: 'Xác nhận mật khẩu thất bại! Không thể ký.' });
        }
        
        const signature = signDocument(documentBuffer, user.privateKey);
        
        res.json({ 
            success: true, 
            message: 'Đã ký số thành công!',
            signature: signature, 
            signatureImage: user.signatureImage
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi hệ thống khi ký số.' });
    }
});

// ==========================================
// API 4: XÁC MINH TÍNH TOÀN VẸN (Giữ nguyên)
// ==========================================
app.post('/api/verify', upload.single('document'), (req, res) => {
    try {
        const documentBuffer = req.file.buffer;
        const publicKey = req.body.publicKey;
        const signature = req.body.signature;

        const isValid = verifySignature(documentBuffer, signature, publicKey);
        res.json({ success: true, isValid: isValid });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Dữ liệu xác minh bị sai định dạng.' });
    }
});

// ==========================================
// KHỞI ĐỘNG MÁY CHỦ
// ==========================================
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`🚀 Máy chủ đang chạy tại cổng ${PORT}`);
    console.log(`📁 Dữ liệu được lưu an toàn tại file: ${DB_FILE}`);
});