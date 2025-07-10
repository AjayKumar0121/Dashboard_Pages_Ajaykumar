const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 4500 });

const clients = new Set();

wss.on('connection', (ws) => {
  console.log('New client connected');
  clients.add(ws);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'employeeDetails') {
        // Broadcast employee details to all connected clients except the sender
        clients.forEach((client) => {
          if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'employeeDetails',
              details: {
                name: data.details.name,
                email: data.details.email,
                emp_id: data.details.emp_id
              }
            }));
          }
        });
        console.log('Broadcasted employee details:', data.details);
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
    clients.delete(ws);
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    clients.delete(ws);
  });
});

wss.on('listening', () => {
  console.log('WebSocket server running on ws://44.223.23.145:4500');
});

wss.on('error', (error) => {
  console.error('WebSocket server error:', error);
});

// Handle server shutdown gracefully
process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Closing WebSocket server...');
  wss.close(() => {
    console.log('WebSocket server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('Received SIGINT. Closing WebSocket server...');
  wss.close(() => {
    console.log('WebSocket server closed');
    process.exit(0);
  });
});
