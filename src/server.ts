import 'reflect-metadata';
import 'express-async-errors';

import express, { Request, Response, NextFunction } from 'express';
import routes from './routes';
import uploadConfig from './config/upload';
import './database';
import AppError from './errors/AppError';

const app = express();

app.use(express.json())
app.use('/files', express.static(uploadConfig.directory))
app.use(routes);

app.use((err: Error, request: Request, response: Response, _: NextFunction) => {
  if(err instanceof AppError){
    return response.status(err.statusCode).json({
      status: 'error',
      message: err.message
    });
  }

  console.error(err);

  return response.status(500).json({
    status: 'error',
    message: 'Internal server errror',
  })
})
app.listen(3333, () => {
  console.log('Server running');
});
