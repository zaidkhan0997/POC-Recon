export namespace main {
	
	export class ReconRequest {
	    website: string;
	    name: string;
	    person_linkedin: string;
	    company_linkedin: string;
	    proxy_url: string;
	    no_verify: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ReconRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.website = source["website"];
	        this.name = source["name"];
	        this.person_linkedin = source["person_linkedin"];
	        this.company_linkedin = source["company_linkedin"];
	        this.proxy_url = source["proxy_url"];
	        this.no_verify = source["no_verify"];
	    }
	}

}

export namespace models {
	
	export class EmailCandidate {
	    email: string;
	    pattern_name: string;
	    status: string;
	    smtp_code?: number;
	    smtp_message?: string;
	    confidence: number;
	
	    static createFrom(source: any = {}) {
	        return new EmailCandidate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.email = source["email"];
	        this.pattern_name = source["pattern_name"];
	        this.status = source["status"];
	        this.smtp_code = source["smtp_code"];
	        this.smtp_message = source["smtp_message"];
	        this.confidence = source["confidence"];
	    }
	}
	export class MXRecord {
	    host: string;
	    priority: number;
	
	    static createFrom(source: any = {}) {
	        return new MXRecord(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.priority = source["priority"];
	    }
	}
	export class NameParts {
	    first_name: string;
	    middle_name?: string;
	    last_name?: string;
	    full_name: string;
	
	    static createFrom(source: any = {}) {
	        return new NameParts(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.first_name = source["first_name"];
	        this.middle_name = source["middle_name"];
	        this.last_name = source["last_name"];
	        this.full_name = source["full_name"];
	    }
	}
	export class ProviderInfo {
	    name: string;
	    spf_record?: string;
	    details?: string;
	
	    static createFrom(source: any = {}) {
	        return new ProviderInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.spf_record = source["spf_record"];
	        this.details = source["details"];
	    }
	}
	export class ReconResult {
	    target_domain: string;
	    person: NameParts;
	    mx_records: MXRecord[];
	    provider?: ProviderInfo;
	    port_25_open: boolean;
	    is_catch_all: boolean;
	    verification_method: string;
	    candidates: EmailCandidate[];
	    best_candidate?: EmailCandidate;
	    // Go type: time
	    timestamp: any;
	
	    static createFrom(source: any = {}) {
	        return new ReconResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target_domain = source["target_domain"];
	        this.person = this.convertValues(source["person"], NameParts);
	        this.mx_records = this.convertValues(source["mx_records"], MXRecord);
	        this.provider = this.convertValues(source["provider"], ProviderInfo);
	        this.port_25_open = source["port_25_open"];
	        this.is_catch_all = source["is_catch_all"];
	        this.verification_method = source["verification_method"];
	        this.candidates = this.convertValues(source["candidates"], EmailCandidate);
	        this.best_candidate = this.convertValues(source["best_candidate"], EmailCandidate);
	        this.timestamp = this.convertValues(source["timestamp"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

