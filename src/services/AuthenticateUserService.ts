import { getRepository} from 'typeorm'
import User from './../models/User';
import { compare } from 'bcryptjs';
import { sign } from 'jsonwebtoken';
interface Request {
  email: string;
  password: string;
}

interface Response {
  user: User;
  token: string;
}

class AuthenticateUserService {

  public async execute({email, password}: Request): Promise<Response> {
    const usersRepository = getRepository(User);
    const user = await usersRepository.findOne({
      where: { email }
    })

    if(!user){
      throw new Error('Incorrect email/password combination.');
    }

    const passwordMatched = await compare(password, user.password);

    if(!passwordMatched){
      throw new Error('Incorrect email/password combination.');
    }

    const token = sign({}, 'd9664a5417cca408b851c5afb0e44ccb', {
      subject: user.id,
      expiresIn: '1d',
    });
    return { user, token }
  }
}

export default AuthenticateUserService;
