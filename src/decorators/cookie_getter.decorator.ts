import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';

export const CookieGetter = createParamDecorator(
  async (data: string, context: ExecutionContext): Promise<string> => {
    const request = context.switchToHttp().getRequest();

    const refresToken = request.cookies[data];

    if (!refresToken) {
      throw new UnauthorizedException('token is not found');
    }
    return refresToken;
  },
);
