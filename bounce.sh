pm2 stop curator-server
pm2 delete curator-server
pm2 start server.js --name curator-server -i 1
