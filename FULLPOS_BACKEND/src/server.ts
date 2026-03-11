import http from 'http';
import app from './app';
import env from './config/env';
import { prisma } from './config/prisma';
import { attachRealtimeGateway } from './realtime/realtime.gateway';

const port = env.PORT;

async function bootstrap() {
  await prisma.$connect();
  const server = http.createServer(app);
  attachRealtimeGateway(server);
  server.listen(port, () => {
    console.log(`FULLPOS backend running on port ${port}`);
  });
}

bootstrap().catch((err) => {
  console.error('Failed to start server', err);
  process.exit(1);
});
