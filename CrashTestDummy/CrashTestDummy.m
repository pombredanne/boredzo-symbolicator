//
//  CrashTestDummy.m
//  CrashTestDummy
//
//  Created by Peter Hosey on 2009-04-27.
//  Copyright 2009 Peter Hosey. All rights reserved.
//

#import "CrashTestDummy.h"

@interface CrashTestDummy ()

- (void) crashByThrowingACocoaException;
- (void) crashByAccessingBadMemory;
- (void) crashByRecursingInfinitely;

@end


@implementation CrashTestDummy

- (id) init {
	if((self = [super init])) {
		threadToCrashOn = CTDThreadMain;
		crashType = CTDCrashTypeCocoaException;

		windowController = [[NSWindowController alloc] initWithWindowNibName:@"CrashTestDummy" owner:self];
		[windowController showWindow:nil];
	}
	return self;
}
- (void) dealloc {
	[windowController close];
	[windowController release];
	[super dealloc];
}

@synthesize threadToCrashOn;
@synthesize crashType;

- (IBAction) crash:(id) sender {
	SEL weaponOfChoice = NULL;
	switch (self.crashType) {
		case CTDCrashTypeCocoaException:
			weaponOfChoice = @selector(crashByThrowingACocoaException);
			break;

		case CTDCrashTypeBadMemoryAccess:
			weaponOfChoice = @selector(crashByAccessingBadMemory);
			break;

		case CTDCrashTypeStackOverflow:
			weaponOfChoice = @selector(crashByRecursingInfinitely);
			break;

		default:;
			NSAlert *alert = [NSAlert alertWithMessageText:NSLocalizedString(@"Could not crash", @"Alert message text")
											 defaultButton:nil
										   alternateButton:nil
											   otherButton:nil
								 informativeTextWithFormat:NSLocalizedString(@"In an unusual turn of events, a bug in this application prevented the application from crashing. Please report the bug to the developers, and mention the failed-crash type \"%lu\".", @"Alert informative text"),
							  (unsigned long)(self.crashType)];
			[alert beginSheetModalForWindow:[windowController window]
							  modalDelegate:nil
							 didEndSelector:NULL
								contextInfo:NULL];
			break;
	}

	if (!weaponOfChoice)
		return;

	if (self.threadToCrashOn == CTDThreadSecondary)
		[self performSelectorInBackground:weaponOfChoice withObject:nil];
	else if (self.threadToCrashOn == CTDThreadMain)
		[self performSelector:weaponOfChoice withObject:nil];
}


- (void) crashByThrowingACocoaException {
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	@try {
		@throw([NSException exceptionWithName:NSInternalInconsistencyException reason:@"Exception requested by user" userInfo:nil]);
	}
	@finally {
		[pool drain];
	}
}
- (void) crashByAccessingBadMemory {
	char *ptr = (char *)1;
	*ptr = 42; //BOOM
}
- (void) crashByRecursingInfinitely {
	[self crashByRecursingInfinitely];
}

@end
