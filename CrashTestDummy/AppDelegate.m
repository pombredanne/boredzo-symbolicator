//
//  AppDelegate.m
//  CrashTestDummy
//
//  Created by Peter Hosey on 2009-04-27.
//  Copyright 2009 Peter Hosey. All rights reserved.
//

#import "AppDelegate.h"

#import "CrashTestDummy.h"

@implementation AppDelegate

- (void) applicationWillFinishLaunching:(NSNotification *)notification {
	dummy = [[CrashTestDummy alloc] init];
}
- (void) applicationWillTerminate:(NSNotification *)notification {
	[dummy release];
}

@end
