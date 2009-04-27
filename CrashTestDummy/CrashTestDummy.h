//
//  CrashTestDummy.h
//  CrashTestDummy
//
//  Created by Peter Hosey on 2009-04-27.
//  Copyright 2009 Peter Hosey. All rights reserved.
//

enum {
	CTDThreadMain,
	CTDThreadSecondary
};

enum {
	CTDCrashTypeCocoaException,
	CTDCrashTypeBadMemoryAccess,
	CTDCrashTypeStackOverflow,
	CTDNumberOfCrashTypes
};

@interface CrashTestDummy : NSObject {
	NSWindowController *windowController;
	NSUInteger threadToCrashOn;
	NSUInteger crashType;
}

@property NSUInteger threadToCrashOn;
@property NSUInteger crashType;

- (IBAction) crash:(id) sender;

@end
