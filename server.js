const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const path = require('path');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
const cookieParser = require('cookie-parser');
app.use(cookieParser()); // 啟用 Cookie 解析
const port = process.env.PORT || 3000;

const secretKey = 'your_secret_key';
const { poolPromise, sql } = require('./db'); // 將 poolPromise 和 sql 從 db.js 引入
require('dotenv').config();
console.log('SECRET_KEY:', process.env.SECRET_KEY); // 測試是否正確載入

const authenticateToken = (req, res, next) => {
    const token = req.cookies.token; // 確保 Cookie 解析啟用
    if (!token) return res.status(403).send('未授權');

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) return res.status(403).send('驗證失敗');
        req.user = user; // 添加 user 信息到 req
        next();
    });
};
// 註冊路由
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const pool = await poolPromise;
        const query = `INSERT INTO powerBIusers (username, password) VALUES (@username, @password)`;
        await pool.request()
            .input('username', sql.VarChar, username)
            .input('password', sql.VarChar, hashedPassword)
            .query(query);
        res.redirect('/'); // 重定向回首頁
    } catch (err) {
        console.error('註冊失敗:', err);
        if (err.number === 2627) { // UNIQUE 約束違反
            res.send('用戶名已存在，請選擇其他用戶名！');
        } else {
            res.status(500).send('伺服器錯誤，請稍後再試！');
        }
    }
});




// 測試首頁
app.get('/', (req, res) => {
    res.render('index');
});

// 登入路由
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const pool = await poolPromise;
        const query = `SELECT * FROM powerBIusers WHERE username = @username`;
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .query(query);

        if (result.recordset.length === 0) {
            return res.send('用戶不存在！');
        }

        const validPassword = await bcrypt.compare(password, result.recordset[0].password);
        if (validPassword) {
            const token = jwt.sign({ id: result.recordset[0].id }, process.env.SECRET_KEY, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true }); // 使用 HttpOnly 改善安全性
            res.redirect('/dashboard'); // 登入成功後跳轉到儀表板
        } else {
            res.send('密碼錯誤，請重試！');
        }
    } catch (err) {
        console.error('登入失敗:', err);
        res.status(500).send('伺服器錯誤');
    }
});

// 測試登入頁面
app.get('/login', (req, res) => {
    res.render('login'); // 確保此處正確渲染 login.ejs
});
// 註冊頁面路由
app.get('/register', (req, res) => {
    res.render('register'); // 渲染 register.ejs
});

app.get('/dashboard', authenticateToken, (req, res) => {
    res.render('dashboard'); // 渲染 dashboard.ejs
});

app.get('/report1', (req, res) => {
    res.render('report', { reportId: 'your_report1_embed_url' });
});

app.get('/report2', (req, res) => {
    res.render('report', { reportId: 'your_report2_embed_url' });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token'); // 清除儲存在 Cookie 中的 JWT Token
    res.redirect('/'); // 重定向回首頁
});

app.listen(port, () => {
    console.log('Server is running on http://localhost:3000');
});