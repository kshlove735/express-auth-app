const cookieParser = require('cookie-parser');
const express = require('express');
const jwt = require('jsonwebtoken')

const app = express();
const secretText = 'superSecret';
const refreshSecretText = 'supersuperSecret'
const posts = [
    {
        username: 'John',
        title: 'Post 1'
    },
    {
        username: 'Han',
        title: 'Post 2'
    }
]


app.use(express.json());    // client 측에서 보낸 body 정보 받아 올 수 있게 한다.
app.use(cookieParser())

let refreshTokens = [];
app.post('/login', (req, res) => {
    const username = req.body.username
    const user = { name: username }

    // jwt를 이용해서 accessToken 생성 : payload + secretText + 유효기간
    const accessToken = jwt.sign(user, secretText, { expiresIn: '30s' });
    // refreshToken 생성
    const refreshToken = jwt.sign(user, refreshSecretText, { expiresIn: '1d' })

    refreshTokens.push(refreshToken);


    // refreshToken을 쿠키에 넣어주기
    res.cookie('jwt', refreshToken, {
        httpOnly: true, // javascript를 이용해서 탈취하거나 조작할 수 없게 만든다.(XSS Cross Site Script 공격 방어)
        maxAge: 24 * 60 * 60 * 1000,
    })

    res.json({ accessToken: accessToken })
})


app.get('/posts', authMiddleware, (req, res) => {
    res.json(posts)
})


function authMiddleware(req, res, next) {
    //  토큰을 request headers에서 가져오기
    const authHeader = req.headers['authorization'];
    // Bearer sdklfjsdlfl.lsdkjfls.lsdfkjlsd
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401);

    // 토큰이 유효한 토큰인지 확인
    jwt.verify(token, secretText, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;    // 다른 라우터에서 req.user로 user를 호출 할 수 있다.
        next();
    })

}

app.get('/refresh', (req, res) => {
    // cookie-parser 이용하여 cookies 가져오기
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);

    const refreshToken = cookies.jwt;
    // refreshToken이 데이터베이스에 있는 토큰인지 확인
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

    // token이 유효한지 확인
    jwt.verify(refreshToken, refreshSecretText, (err, user) => {
        if (err) return res.sendStatus(403);
        // 새로운 accessToken 생성하기
        const accessToken = jwt.sign({ name: user.name }, secretText, { expiresIn: '30s' })
        res.json({ accessToken })
    })
})

const port = 4000;
app.listen(port, () => {
    console.log(`listening on port ${port}`);
})

