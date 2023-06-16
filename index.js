const express = require('express');
const jwt = require('jsonwebtoken')

const app = express();
const secretText = 'superSecret';

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

app.post('/login', (req, res) => {
    const username = req.body.username
    const user = { name: username }

    // jwt를 이용해서 토근 생성 : payload + secretText
    const accessToken = jwt.sign(user, secretText);
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

const port = 4000;
app.listen(port, () => {
    console.log(`listening on port ${port}`);
})

