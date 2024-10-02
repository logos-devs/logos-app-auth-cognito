import {CognitoServicePromiseClient} from "app/auth/cognito/proto/cognito_grpc_web_pb.js";
import {AppModule, registerModule} from "external/logos~/dev/logos/web/module/app-module";
import {User} from "external/logos~/dev/logos/web/module/user";
import {injectable} from "inversify";
import {action, autorun, observable} from 'mobx';

@injectable()
export class CognitoUser extends User {
    @observable
    public isAuthenticated: boolean = false;

    constructor() {
        super();
    }
}

@registerModule
export class AuthModule extends AppModule {
    override configure() {
        this.bind(User).to(CognitoUser);
        this.bind(CognitoUser).to(CognitoUser);
        this.addClient(CognitoServicePromiseClient);
    }
}
